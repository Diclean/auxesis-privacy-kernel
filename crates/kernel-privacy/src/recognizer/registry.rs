//! The registry: the mounted recognisers, and the pipeline that runs them.

use std::cell::Cell;
use std::sync::Arc;

use crate::context::ContextEnhancer;
use crate::decode::{self, DecodedText};
use crate::email_layer::EmailLayer;
use crate::normalize::{NormalizedText, SharedViews};
use crate::recognizers;
use crate::span::{EntityKind, Span};
use crate::threshold::Thresholds;

use super::builder::RegistryBuilder;
use super::constants::{COMPOSITION_ROUNDS, GENERIC_FALLBACK_SCORE, UNVERIFIED_SCORE};
use super::detector::Recognizer;
use super::markers::{is_bracket, marker_runs, token_around, widen_over_runs};
use super::overlap::resolve_overlaps;
use super::person::expand_person_spans;
use super::pipeline::{chain_bounds, chain_text, still_encoded, Chain, Folds, SourceBounds, Step};
use super::spans::{span_is_well_formed, split_long_spans};
use super::{extend_hyphenated_persons, MARKER_RUN, NAME_WIDENED};

/// A set of recognisers plus the context enhancer and thresholds they run
/// under.
pub struct Registry {
    pub(super) recognizers: Vec<Box<dyn Recognizer>>,
    pub(super) context: ContextEnhancer,
    pub(super) thresholds: Thresholds,
    /// The email-aware post-pass. `None` reproduces the behaviour without it
    /// exactly, which the eval harness uses as its "before" arm.
    pub(super) email_layer: Option<EmailLayer>,
    /// Whether person and organisation spans reach the overlap merge. A private
    /// gate turns this off: a name dropped only after the merge
    /// would take the hard value it overlapped with it.
    pub(super) keep_names: bool,
}

impl Registry {
    /// The default registry: every recogniser, default context and thresholds,
    /// and the email-aware layer.
    ///
    /// The unverified rules (NIR, SIRET, passport MRZ) are mounted too: their
    /// spans are relabelled `NATIONAL_ID` at a lower score, never dropped.
    pub fn new() -> Self {
        Self {
            recognizers: recognizers::default_recognizers(),
            context: ContextEnhancer::new(),
            thresholds: Thresholds::new(),
            email_layer: Some(EmailLayer::new()),
            keep_names: true,
        }
    }

    /// This registry without its person and organisation spans. They are
    /// dropped before the overlap merge, so every other span merges and masks
    /// on its own: a name can never widen over, relabel or remove a hard value.
    /// Public so the eval scores what private mode really masks.
    pub fn without_names(mut self) -> Self {
        self.keep_names = false;
        self
    }

    /// A builder for a custom registry.
    pub fn builder() -> RegistryBuilder {
        RegistryBuilder {
            recognizers: Vec::new(),
            context: ContextEnhancer::new(),
            thresholds: Thresholds::new(),
            email_layer: Some(EmailLayer::new()),
        }
    }

    /// The mounted recognisers, in run order.
    pub fn recognizers(&self) -> &[Box<dyn Recognizer>] {
        &self.recognizers
    }

    /// The thresholds in force.
    pub fn thresholds(&self) -> &Thresholds {
        &self.thresholds
    }

    /// The email-aware layer, when mounted.
    pub fn email_layer(&self) -> Option<&EmailLayer> {
        self.email_layer.as_ref()
    }

    /// Run every recogniser and return the surviving spans, ordered by start
    /// offset. Overlapping or adjacent spans of every kind are merged into the
    /// exact union of the bytes a caller must mask, so the returned regions are
    /// non-overlapping and cover every detected byte once. A `PERSON` span that
    /// overlaps an email, URL or phone region takes that region's
    /// highest-priority kind; a name alone keeps its `PERSON` kind.
    ///
    /// The pipeline fails toward masking:
    ///
    /// * a span from an unverified recogniser is relabelled `NATIONAL_ID` at
    ///   [`UNVERIFIED_SCORE`], so it is masked without claiming a specific rule;
    /// * a checksum-valid span whose score stays below its kind's floor (no cue)
    ///   is relabelled `NATIONAL_ID` at [`GENERIC_FALLBACK_SCORE`] rather than
    ///   dropped;
    /// * every surviving span longer than [`MAX_SPAN_BYTES`](crate::recognizer::MAX_SPAN_BYTES) is split.
    ///
    /// When the email-aware layer is mounted, every `PERSON` span any recogniser
    /// produced — including one below its floor — seeds name propagation, and
    /// the layer adds its own decoded, greeting, company-id and tracking spans
    /// before the overlap resolution.
    pub fn analyze(&self, text: &str) -> Vec<Span> {
        let mut spans = self.analyze_tagged(text);
        spans.retain(|span| span.recognizer != NAME_WIDENED);
        spans
    }

    /// [`Registry::analyze`], plus, for a registry without names, each
    /// [`NAME_WIDENED`] region after the merged ones (it overlaps them).
    pub(crate) fn analyze_tagged(&self, text: &str) -> Vec<Span> {
        let layer = self.email_layer.as_ref();
        let glyph = Cell::new(false);
        let main = self.analyze_with(text, layer, Folds::Main, &glyph);
        if !glyph.get() {
            return main;
        }
        // Some view held a full-width `＆`, `＃` or `％`, so the glyph
        // folds may read an escape the main folds leave alone. The whole pipeline
        // runs again on those folds, and the masks are the union of both runs:
        // every main region stays covered, with its prohibited kind
        // ([`resolve_overlaps`]), so the extra run can only add masks.
        let extra = self.analyze_with(text, layer, Folds::Glyph, &glyph);
        let (widened, spans): (Vec<Span>, Vec<Span>) = main
            .into_iter()
            .chain(extra)
            .partition(|span| span.recognizer == NAME_WIDENED);
        let mut regions = split_long_spans(text, resolve_overlaps(spans));
        regions.extend(widened);
        regions
    }

    /// The deterministic recognisers only: the same pipeline with no e-mail
    /// layer, so no name heuristic runs. The gate's residue scan reads text
    /// through this view, because the layer's name cues depend on the words
    /// around a value, and masking changes those words.
    ///
    /// It reads the main folds only, never the glyph ones: a refusal comes
    /// from this scan, so what refuses is exactly what refused before the extra
    /// views existed.
    pub fn analyze_values(&self, text: &str) -> Vec<Span> {
        let mut spans = self.analyze_with(text, None, Folds::Main, &Cell::new(false));
        spans.retain(|span| span.recognizer != NAME_WIDENED);
        spans
    }

    /// Run every recogniser over `view`. For a decoded or folded view, `mapped`
    /// holds its map back and the original text: a span is mapped back before
    /// it is kept.
    fn scan(
        &self,
        view: &str,
        mapped: Option<(&SourceBounds<'_>, &str)>,
        candidates: &mut Vec<Span>,
        seeds: &mut Vec<Span>,
    ) {
        let _views = SharedViews::new(view);
        for recognizer in &self.recognizers {
            let verified = recognizer.verified();
            let found = match mapped {
                Some((source_bounds, original)) => {
                    recognizer.analyze_with_source(view, original, source_bounds)
                }
                None => recognizer.analyze(view),
            };
            for mut span in found {
                if !span_is_well_formed(view, &span) {
                    continue;
                }
                if !verified {
                    span.kind = EntityKind::NationalId;
                    span.score = span.score.min(UNVERIFIED_SCORE);
                }
                self.context.enhance(view, &mut span);
                if let Some((source_bounds, original)) = mapped {
                    let Some((start, end)) = source_bounds(span.start, span.end) else {
                        continue;
                    };
                    span.start = start;
                    span.end = end;
                    if !span_is_well_formed(original, &span) {
                        continue;
                    }
                }
                if span.kind == EntityKind::Person {
                    seeds.push(span);
                }
                if span.score >= self.thresholds.get(span.kind) {
                    candidates.push(span);
                    continue;
                }
                if span.kind == EntityKind::NationalId {
                    continue;
                }
                let mut generic = span;
                generic.kind = EntityKind::NationalId;
                generic.score = GENERIC_FALLBACK_SCORE;
                if generic.score >= self.thresholds.get(EntityKind::NationalId) {
                    candidates.push(generic);
                }
            }
        }
    }

    /// The pipeline over one set of folds. `glyph` is set when a text it folds
    /// holds a character the glyph folds may read another way.
    fn analyze_with(
        &self,
        text: &str,
        layer: Option<&EmailLayer>,
        folds: Folds,
        glyph: &Cell<bool>,
    ) -> Vec<Span> {
        let folded_views = |view: &str| folds.views(view, glyph);
        let mut candidates: Vec<Span> = Vec::new();
        let mut seeds: Vec<Span> = Vec::new();
        self.scan(text, None, &mut candidates, &mut seeds);
        let runs = self.scan_decoded_views(text, &folded_views, &mut candidates, &mut seeds);
        if let Some(layer) = layer {
            candidates = layer.apply(text, candidates, &seeds);
        }
        self.scan_escaped_views(text, &folded_views, &mut candidates, &mut seeds);
        // A value that touches a marker's run takes the whole run: dropping the
        // marker may have joined or split it. A run no view finds a value in
        // stays text (`⟦x + 1⟧`). A gate that keeps the session's own tokens
        // blanks them before detection, so they are never runs.
        widen_over_runs(&mut candidates, &runs);
        self.resolve_regions(text, candidates)
    }

    /// Scan the decoded views of `text`, every fold of one and every fold of
    /// the raw text, and compose decoding with folding. Returns the marker runs.
    fn scan_decoded_views(
        &self,
        text: &str,
        folded_views: &dyn Fn(&str) -> Vec<NormalizedText>,
        candidates: &mut Vec<Span>,
        seeds: &mut Vec<Span>,
    ) -> Vec<(usize, usize)> {
        // A value written with HTML entities (`chimioth&eacute;rapie`,
        // `sk&#45;key`) is invisible to a recogniser on the raw bytes. The
        // recognisers read the decoded view too, and a span maps back to every
        // source byte of the value, so masking never depends on a name rule.
        // A text decoding leaves alone has no marker and no decoded view: do
        // not build one (every ASCII text without `&` or `%`).
        let decoded = (!DecodedText::is_unchanged(text)).then(|| DecodedText::new(text));
        let runs: Vec<(usize, usize)> = decoded
            .as_ref()
            .map_or_else(Vec::new, |view| marker_runs(text, view.markers()));
        let mut views: Vec<DecodedText> = decoded.into_iter().collect();
        if views.first().is_some_and(DecodedText::dropped_marker_body) {
            // A value inside a `⟦…⟧` pair: read it with only the brackets gone.
            views.push(DecodedText::brackets_only(text));
        }
        // Every marked text is also read with each bracket as a space, so a
        // value a bracket touches keeps its boundary (`texte⟦sk-…⟧`,
        // `1⟦sk-…⟧`). A test on the dropped view's markers is not enough: a
        // nested or unbalanced bracket (`⟦1⟦sk-…⟧ ⟧`) hides inside the outer
        // pair that view drops whole.
        if views.first().is_some_and(|view| !view.markers().is_empty()) {
            views.push(DecodedText::brackets_as_spaces(text));
        }
        // A marker between two letters splices a word (`chimioth⟦X⟧éra⟦pie ⟧`):
        // its run fails closed. Maths and markdown put markers at word edges.
        let spliced = views.iter().filter(|view| view.mode_drops_brackets());
        for view in spliced {
            for &marker in view.markers() {
                if view.marker_joins_letters(marker) {
                    let at = runs.partition_point(|run| run.1 <= marker.0);
                    if let Some(&(start, end)) = runs.get(at) {
                        candidates.push(Span::new(EntityKind::Secret, start, end, 1.0, MARKER_RUN));
                    }
                }
            }
        }
        // Every decoded view, every fold of one and every
        // fold of the raw text are the first round of the composition below.
        let mut frontier: Vec<Chain> = Vec::new();
        for view in views.into_iter().filter(|view| view.text() != text) {
            let decoded = Arc::new(view);
            let chain = [Step::Decoded(Arc::clone(&decoded))];
            self.scan_chain(&chain, text, candidates, seeds);
            // Still encoded at the pass cap: the whole token is masked.
            for &(start, end) in decoded.unresolved() {
                candidates.push(Span::new(EntityKind::Secret, start, end, 1.0, "decode-cap"));
            }
            // A look-alike behind an entity (`di&#1072;betes`): the decoded view
            // is folded too, and a span maps back through both maps. Each view
            // is the first round of a [`Chain`] the composition extends.
            for folded in folded_views(decoded.text()) {
                let mut folded_chain = chain.to_vec();
                folded_chain.push(Step::Folded(folded));
                self.scan_chain(&folded_chain, text, candidates, seeds);
                frontier.push(folded_chain);
            }
            frontier.push(chain.to_vec());
        }
        // Look-alike, full-width, mathematical and invisible characters
        // read as the ASCII they stand for, and a span maps back to every byte.
        for view in folded_views(text) {
            let chain = vec![Step::Folded(view)];
            self.scan_chain(&chain, text, candidates, seeds);
            frontier.push(chain);
        }
        // Decoding and folding compose.
        self.compose(&mut frontier, text, folded_views, candidates, seeds);

        runs
    }

    /// Scan the escape-decoded views of `text`. Callers run this after the
    /// e-mail layer so a new view cannot displace a mask it selected.
    fn scan_escaped_views(
        &self,
        text: &str,
        folded_views: &dyn Fn(&str) -> Vec<NormalizedText>,
        candidates: &mut Vec<Span>,
        seeds: &mut Vec<Span>,
    ) {
        // Append the new decoded views after the original pipeline, so they
        // cannot displace a mask selected by the existing e-mail layer.
        let escaped = text
            .match_indices(['\\', '%', '&'])
            .any(|(at, _)| decode::known_escape_at(text, at, &|_, _| None))
            .then(|| DecodedText::escaped(text, false))
            .flatten();
        if let Some(escaped) = escaped {
            let brackets = escaped
                .dropped_marker_body()
                .then(|| DecodedText::escaped(text, true))
                .flatten();
            for view in std::iter::once(escaped).chain(brackets) {
                for &(start, end) in view.unresolved() {
                    candidates.push(Span::new(EntityKind::Secret, start, end, 1.0, "escape-cap"));
                }
                if view.text() != text {
                    let chain = vec![Step::Decoded(Arc::new(view))];
                    self.scan_chain(&chain, text, candidates, seeds);
                    for folded in folded_views(chain_text(&chain)) {
                        let mut next = chain.clone();
                        next.push(Step::Folded(folded));
                        self.scan_chain(&next, text, candidates, seeds);
                    }
                }
            }
        }
    }

    /// Merge the candidates into masked regions, adding the name-widened
    /// regions when this registry drops names before the merge.
    fn resolve_regions(&self, text: &str, mut candidates: Vec<Span>) -> Vec<Span> {
        let regions = |spans: Vec<Span>| {
            let expanded = expand_person_spans(text, extend_hyphenated_persons(text, spans));
            split_long_spans(text, resolve_overlaps(expanded))
        };
        if self.keep_names {
            return regions(candidates);
        }
        // A name never masks on its own here, but the registry with names, and
        // Open mode, hide every byte the merge with names gave a prohibited
        // region. Such a region is appended, tagged [`NAME_WIDENED`], when it
        // reads a letter or digit the regions without names leave clear; the
        // gate masks it after its main rounds.
        let named = regions(candidates.clone());
        candidates
            .retain(|span| !matches!(span.kind, EntityKind::Person | EntityKind::Organization));
        let mut plain = regions(candidates);
        let widened: Vec<Span> = named
            .into_iter()
            .filter(|region| region.is_prohibited() && adds_readable(text, region, &plain))
            .map(|region| Span {
                recognizer: NAME_WIDENED,
                ..region
            })
            .collect();
        plain.extend(widened);
        plain
    }

    /// Scan a composed view: the text its last step reads, and its map back to
    /// `original` through every step of the chain.
    fn scan_chain(
        &self,
        chain: &[Step],
        original: &str,
        candidates: &mut Vec<Span>,
        seeds: &mut Vec<Span>,
    ) {
        let bounds = |start, end| chain_bounds(chain, start, end);
        self.scan(
            chain_text(chain),
            Some((&bounds, original)),
            candidates,
            seeds,
        );
    }

    /// Decoding and folding compose, because a fold creates escapes of
    /// its own — `&#65286;` decodes to `＆`, whose fold supplies the `&` of
    /// `&#105;`, which a second decode reads as the `i` of `sk-proj`, and that
    /// folds again (`о` reads as `o`).
    ///
    /// Every chain of `frontier` is decoded again and each fold of it is scanned
    /// too, [`COMPOSITION_ROUNDS`] rounds deep; a chain keeps the map of every
    /// step, so a span still covers all of the source bytes of its value. Never
    /// recursive, always linear: a fixed number of rounds of linear passes.
    fn compose(
        &self,
        frontier: &mut Vec<Chain>,
        text: &str,
        folded_views: &dyn Fn(&str) -> Vec<NormalizedText>,
        candidates: &mut Vec<Span>,
        seeds: &mut Vec<Span>,
    ) {
        for _ in 1..COMPOSITION_ROUNDS {
            let mut next: Vec<Chain> = Vec::new();
            for chain in frontier.iter() {
                let view = chain_text(chain);
                // Nothing left to decode: an entity needs `&`, a percent escape
                // `%`, and every marker or invisible character is outside ASCII.
                if view.is_ascii() && !view.contains(['&', '%']) {
                    continue;
                }
                let decoded = Arc::new(DecodedText::brackets_only(view));
                if decoded.text() == view {
                    continue;
                }
                let mut decoded_chain = chain.clone();
                decoded_chain.push(Step::Decoded(Arc::clone(&decoded)));
                // A marker this round decoded that the view spells no bracket is
                // a bracket an escape produced, and an escape a fold created is
                // one no real token spells: a token marker is written plainly.
                // Whatever the round did with the body behind it, the token
                // around it is masked whole.
                for &marker in decoded.markers() {
                    if is_bracket(view.get(marker.0..marker.1).unwrap_or_default()) {
                        continue;
                    }
                    let Some(bounds) = chain_bounds(&decoded_chain, marker.0, marker.1) else {
                        continue;
                    };
                    let (from, to) = token_around(text, bounds.0, bounds.1);
                    candidates.push(Span::new(
                        EntityKind::Secret,
                        from,
                        to,
                        1.0,
                        "compose-marker",
                    ));
                }
                // The decoded view, then each fold of it. A view that already
                // reads as ASCII folds to itself, so on its own the decoded view
                // is what this round adds.
                let folds = folded_views(decoded.text());
                if folds.is_empty() {
                    next.push(decoded_chain.clone());
                }
                for folded in folds {
                    let mut chain = decoded_chain.clone();
                    chain.push(Step::Folded(folded));
                    next.push(chain);
                }
            }
            for chain in &next {
                self.scan_chain(chain, text, candidates, seeds);
            }
            // Converged: no view of the last round decodes to something else.
            if next.is_empty() {
                *frontier = next;
                return;
            }
            *frontier = next;
        }
        // The cap is reached with work left. Fail closed: a spelling this deep
        // is not a real one, so every source region a further pass would still
        // change stays masked rather than read as clear.
        for chain in frontier.iter() {
            for (start, end) in still_encoded(chain) {
                candidates.push(Span::new(
                    EntityKind::Secret,
                    start,
                    end,
                    1.0,
                    "compose-cap",
                ));
            }
        }
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether `region` holds a letter or digit no span of `plain` (sorted,
/// disjoint) covers. One cursor over the plain spans the region overlaps.
fn adds_readable(text: &str, region: &Span, plain: &[Span]) -> bool {
    let mut at = plain.partition_point(|span| span.end <= region.start);
    let mut cursor = region.start;
    while cursor < region.end {
        let next = plain.get(at).filter(|span| span.start < region.end);
        let gap_end = next.map_or(region.end, |span| span.start.max(cursor));
        if text[cursor..gap_end].chars().any(char::is_alphanumeric) {
            return true;
        }
        let Some(span) = next else { break };
        cursor = cursor.max(span.end);
        at += 1;
    }
    false
}
