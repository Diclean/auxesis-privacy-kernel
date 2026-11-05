//! The text types a gate issues: [`SafeText`] and [`SafeValue`], the name
//! coverage they carry, and the crate-private fixed marker that needs no grant.

use serde::Serialize;
use serde_json::Value;

use super::detector::{without_names, StandardDetector, PRIVATE_DETECTOR};
use super::seams::{Origin, WITHHELD};

/// Whether the gate's detection covered person and organisation names.
///
/// The deterministic recognisers find a name only through the e-mail layer's
/// cues (a greeting, a sign-off, a header). A full name in running prose needs
/// a name detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameCoverage {
    /// A name detector ran on the text.
    Checked,
    /// No name detector was mounted: names may be unmasked in this text.
    NotChecked,
    /// Written by the application itself, never by a user, a tool result or a
    /// memory row: no detector runs on it, and none is needed.
    AppAuthored,
}

impl NameCoverage {
    /// The coverage of text built from `parts`: any unchecked part leaves the
    /// whole unchecked, and application text alone is app-authored.
    fn of_parts(parts: impl IntoIterator<Item = NameCoverage>) -> Self {
        parts
            .into_iter()
            .fold(Self::AppAuthored, |acc, part| match (acc, part) {
                (Self::NotChecked, _) | (_, Self::NotChecked) => Self::NotChecked,
                (Self::Checked, _) | (_, Self::Checked) => Self::Checked,
                _ => Self::AppAuthored,
            })
    }
}

/// Text that may leave the device: every detected value has been replaced by
/// a token. Issued by [`Gate::text`](super::Gate::text), the only public constructor.
///
/// There is no public grantless mint. The old `trusted_static` accepted
/// `Box::leak`, `OnceLock` and `LazyLock` runtime data; the round-1
/// `safe_text_literal!`/`__from_literal` pair reopened the same hole, because
/// a `&'static str` is what `Box::leak` returns. Both are gone:
///
/// ```compile_fail,E0599
/// let leaked: &'static str = Box::leak(String::from("Élise Vautrin").into_boxed_str());
/// let _ = kernel_privacy::safetext::SafeText::trusted_static(leaked);
/// ```
///
/// ```compile_fail,E0599
/// let _ = kernel_privacy::safetext::SafeText::__from_literal("[auxesis]");
/// ```
///
/// Fixed kernel-authored markers do not need a grant: they go through the
/// crate-private `KernelMarker` enum, whose variants are constants written in
/// this file and which nothing outside `kernel-privacy` can name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SafeText {
    pub(super) text: String,
    #[serde(skip)]
    pub(super) names: NameCoverage,
    /// Where the kernel wrote into the text: what a join keeps and reads as
    /// a stand-in.
    #[serde(skip)]
    pub(super) origin: Origin,
}

/// A fixed, kernel-authored string that may be issued as a [`SafeText`]
/// without a grant.
///
/// The enum is `pub(crate)` and every variant maps to a constant written in
/// this file ([`Self::as_str`]), so nothing outside `kernel-privacy` can name
/// a variant and no variant carries caller data. This is the **only** grantless
/// path left: a refusal placeholder, or another fixed marker kernel code shows
/// in place of a value it refused to send. Dynamic text always goes through
/// [`Gate::text`], which needs a [`Grant`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
pub(crate) enum KernelMarker {
    /// Shown in place of a value the gate refused to issue.
    RefusalPlaceholder,
}

#[cfg(test)]
impl KernelMarker {
    /// The fixed text of this marker, written here and nowhere else.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::RefusalPlaceholder => WITHHELD,
        }
    }
}

impl SafeText {
    /// Mint the fixed text of a `KernelMarker`.
    ///
    /// `pub(crate)`: reachable only from `kernel-privacy` source, and only with
    /// a `KernelMarker` value, whose every variant is a constant written in
    /// this file. No variant takes a caller string, so this cannot mint runtime
    /// data — `Box::leak` has nothing to leak into. A `&Grant` is deliberately
    /// not required, because no caller-supplied byte reaches the text.
    #[cfg(test)]
    pub(crate) fn from_marker(marker: KernelMarker) -> Self {
        let text = marker.as_str().to_string();
        Self {
            origin: Origin::marker(text.len()),
            text,
            names: NameCoverage::AppAuthored,
        }
    }

    /// The parts, in order, as one text. Each part was checked on its own when
    /// it was issued, and the joined text is read again across the seams: a
    /// value only a seam shows (half an IBAN in each part, a label and its
    /// secret, an ID cut over two lines), and the rest of a value a part
    /// already masked in part (a URL, a term, a number cut at the seam), is
    /// replaced with a fixed marker (`[<class> removed]`, or `[value
    /// removed]`). A value of a class open mode leaves in clear stays in clear
    /// when every part it touches is open. Every token and marker the kernel
    /// wrote into a part stays as it was, so its tokens restore as before;
    /// parts that hide nothing across a seam join as they were issued. When
    /// the joined text cannot be read, or a value may go on past what the
    /// join reads, the join issues `[auxesis: withheld]` and nothing of its
    /// parts.
    pub fn join(parts: impl IntoIterator<Item = SafeText>) -> Self {
        let parts: Vec<SafeText> = parts.into_iter().collect();
        let detector = PRIVATE_DETECTOR.get_or_init(|| without_names(StandardDetector::new()));
        let (text, names, origin) = match super::seams::join(&parts, detector.as_ref()) {
            Some((text, origin)) => {
                let names = NameCoverage::of_parts(parts.iter().map(|part| part.names));
                (text, names, origin)
            }
            None => (
                WITHHELD.to_string(),
                NameCoverage::AppAuthored,
                Origin::marker(WITHHELD.len()),
            ),
        };
        Self {
            text,
            names,
            origin,
        }
    }

    /// The masked text, read-only.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Whether no name in this text can be unmasked: a name detector checked
    /// it, or the application wrote it. `false` means person and organisation
    /// names may still be in it, unmasked.
    pub fn names_checked(&self) -> bool {
        self.names != NameCoverage::NotChecked
    }
}

/// A JSON value (tool schema, tool-call arguments) whose every string, key
/// and value, has been masked. Issued by [`Gate::value`](super::Gate::value).
///
/// There is deliberately no literal path: no caller in the tree declares a
/// static JSON value, so [`Gate::value`](super::Gate::value) is the only constructor. The removed
/// `trusted_static` accepted a leaked `&'static Value`; the seal's probe no
/// longer compiles:
///
/// ```compile_fail
/// let leaked: &'static serde_json::Value =
///     Box::leak(Box::new(serde_json::json!({ "to": "Élise Vautrin" })));
/// let _ = kernel_privacy::safetext::SafeValue::trusted_static(leaked);
/// ```
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SafeValue {
    pub(super) value: Value,
    #[serde(skip)]
    pub(super) names: NameCoverage,
}

impl SafeValue {
    /// The masked value, read-only.
    pub fn as_value(&self) -> &Value {
        &self.value
    }

    /// Whether every string of this value is covered: checked by a name
    /// detector, or written by the application.
    pub fn names_checked(&self) -> bool {
        self.names != NameCoverage::NotChecked
    }
}
