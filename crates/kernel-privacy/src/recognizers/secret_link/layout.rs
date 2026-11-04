//! Line ownership, paragraphs and the line table for the secret-link scanner.

use super::lex::{closers, deeper_than, is_sentinel, secret_key, shape};
use super::link::sep_len;
use super::{Kind, Line, Shape};

/// Opener spans by pair id (opener order), and (closer offset, id) in closer order.
pub(super) type Pairs = (Vec<(usize, usize)>, Vec<(usize, usize)>);

/// The ownership pass (D2): quotes, fences, block scalars, key blocks and flow
/// regions own their lines, decided before paragraphs and modes. Each owned line is
/// marked `joined`; each closed quote or fence is recorded as a pair.
fn own(text: &str, lines: &mut [Line]) -> Pairs {
    let (mut openers, mut closes) = (Vec::new(), Vec::new());
    let (mut quotes, mut flow) = (Vec::<(char, usize)>::new(), Vec::<bool>::new());
    let (mut fence, mut scalar, mut block) = (None::<(char, usize, usize)>, None, None);
    let (mut pending, mut cand, mut rest) = (None::<usize>, None, false);
    let count = lines.len();
    for i in 0..count {
        let (start, end) = (lines[i].start, lines[i].end);
        let (raw, indent) = (&text[start..end], &text[start..lines[i].indent]);
        let spaces = raw.len() - raw.trim_start_matches(' ').len();
        let run = |ch: char| raw[spaces..].chars().take_while(|&c| c == ch).count();
        let (mut top, mut keyed, mut flow_at, quoted) = (false, false, None, !quotes.is_empty());
        if rest || quoted {
            (lines[i].joined, keyed) = (true, block.is_some());
            lines[i].taint |= quoted;
            if rest {
                continue;
            }
        } else if let Some((ch, len, id)) = fence {
            lines[i].joined = true;
            if spaces <= 3
                && run(ch) >= len
                && raw[spaces + run(ch)..]
                    .trim_matches([' ', '\t', '\r'])
                    .is_empty()
            {
                (fence, _) = (None, closes.push((start + spaces, id)));
            }
            continue;
        } else if !flow.is_empty() {
            // A flow line inside a key block stays keyed, so a value it continues is masked.
            (lines[i].joined, keyed) = (true, block.is_some());
        } else {
            for (open, kind) in [(&mut scalar, 0), (&mut block, 1)] {
                let Some(k) = *open else { continue };
                if lines[i].shape == Shape::Blank {
                    pending.get_or_insert(i);
                } else if deeper_than(indent, k) || !k.starts_with(indent) {
                    // Deeper, or unsure (tab against spaces): owned, and Prose.
                    lines[i].taint |= !deeper_than(indent, k);
                    let from = pending.take().unwrap_or(i);
                    lines[from..=i]
                        .iter_mut()
                        .for_each(|line| line.joined = true);
                    keyed = kind == 1;
                } else {
                    (*open, pending) = (None, None);
                    lines[i].ends_block |= kind == 1;
                }
                break;
            }
            if pending.is_some() {
                continue;
            }
            top = !lines[i].joined;
            if lines[i].joined && !keyed {
                continue; // block scalar text is literal
            }
        }
        if lines[i].shape == Shape::Fence && !quoted {
            let ch = raw[spaces..].chars().next().unwrap_or('`');
            fence = Some((ch, run(ch), openers.len()));
            openers.push((start + spaces, start + raw.trim_end().len()));
            lines[i].taint = true;
            continue;
        }
        if top {
            cand = None;
            if let Shape::Entry(_, kind, key) = lines[i].shape {
                let secret = secret_key(&text[key.0..key.1]);
                cand = Some((indent, secret, kind == Kind::Header));
                let value = text[key.1..end].trim_start_matches([' ', '\t']);
                let value = value[sep_len(value).unwrap_or(0)..].trim_start_matches([' ', '\t']);
                flow_at = secret.then_some(end - value.len());
            }
        }
        let (mut prev, mut escaped, mut comment) = ((i > 0).then_some('\n'), false, false);
        let mut chars = raw.char_indices().peekable();
        while let Some((at, ch)) = chars.next() {
            let next = chars
                .peek()
                .map(|&(_, ch)| if is_sentinel(ch) { 'x' } else { ch });
            let next = next.or((i + 1 < count).then_some('\n'));
            let ch = if is_sentinel(ch) { 'x' } else { ch };
            let ws = |ch: Option<char>| ch.is_none_or(char::is_whitespace);
            let ambiguous = ws(prev) && ws(next);
            let can_open = !escaped
                && !closers(ch).is_empty()
                && (!"\"'’”»›".contains(ch)
                    || !prev.is_some_and(char::is_alphanumeric) && (!ws(next) || ambiguous));
            if let Some(&(open, id)) = quotes.last() {
                let apostrophe = "'’".contains(ch);
                if !escaped
                    && !ambiguous
                    && !ws(prev)
                    && closers(open).contains(ch)
                    && !(apostrophe && next.is_some_and(char::is_alphanumeric))
                {
                    quotes.pop();
                    closes.push((start + at, id));
                } else if can_open && !ambiguous {
                    quotes.push((ch, openers.len()));
                    openers.push((start + at, start + at + ch.len_utf8()));
                } else if !escaped && "\"'”“’‘»«›‹」』".contains(ch) && !ws(prev) && !apostrophe
                {
                    rest = true;
                    break;
                }
            } else if matches!(ch, '{' | '[')
                && !comment
                && (!flow.is_empty() || keyed || flow_at == Some(start + at))
            {
                flow.push(ch == '{');
            } else if matches!(ch, '}' | ']') && !comment && !escaped && !flow.is_empty() {
                if flow.pop() != Some(ch == '}') {
                    rest = true;
                    break;
                }
            } else if !flow.is_empty() && (ch == '#' && ws(prev) || ch == '/' && next == Some('/'))
            {
                comment = true;
            } else if can_open {
                quotes.push((ch, openers.len()));
                openers.push((start + at, start + at + ch.len_utf8()));
            }
            escaped = ch == '\\' && !escaped;
            prev = Some(ch);
        }
        if !rest && quotes.is_empty() && flow.is_empty() && fence.is_none() {
            match cand.take() {
                Some((k, _, true)) => scalar = Some(k),
                Some((k, true, _)) if block.is_none() => block = Some(k),
                _ => {}
            }
        }
    }
    if rest || !quotes.is_empty() || !flow.is_empty() || fence.is_some() {
        lines[count - 1].taint = true;
    }
    (openers, closes)
}

/// Fill `value_end` for the paragraph `lines[first..=last]`.
fn close(lines: &mut [Line], first: usize, last: usize, config: bool) {
    let end = lines[last].end;
    lines[first..=last]
        .iter_mut()
        .for_each(|line| line.paragraph_end = end);
    if !config {
        lines[first..=last]
            .iter_mut()
            .for_each(|line| line.value_end = end);
        return;
    }
    // Logical lines: an Entry with its Block children, or one line.
    let mut segments: Vec<(usize, usize, bool)> = Vec::new();
    for (i, line) in lines.iter().enumerate().take(last + 1).skip(first) {
        if line.joined {
            if let Some(segment) = segments.last_mut() {
                segment.1 = i;
            }
        } else if line.child {
            while segments.last().is_some_and(|segment| segment.2) {
                segments.pop();
            }
            if let Some(segment) = segments.last_mut() {
                segment.1 = i;
            }
        } else if line.shape != Shape::Blank {
            segments.push((i, i, line.shape == Shape::Structure));
        }
    }
    // A value also takes the Structure lines right after its logical line.
    let mut run = None;
    for &(from, to, structure) in segments.iter().rev() {
        let value_end = run.unwrap_or(0).max(lines[to].end);
        for line in &mut lines[from..=to] {
            line.value_end = value_end;
            line.config = true;
        }
        run = structure.then_some(value_end);
    }
}

/// The line table, with each line's value end, and the closed pairs (Sweep 1).
pub(super) fn line_table(text: &str) -> (Vec<Line>, Pairs) {
    let mut lines = Vec::new();
    let mut start = 0;
    for raw in text.split('\n') {
        let (indent, shape) = shape(raw, start);
        let (end, indent) = (start + raw.len(), start + indent);
        lines.push(Line {
            start,
            end,
            indent,
            shape,
            child: false,
            config: false,
            value_end: end,
            paragraph_end: end,
            joined: false,
            taint: false,
            ends_block: false,
        });
        start = end + 1;
    }
    let pairs = own(text, &mut lines);
    let deeper = |lines: &[Line], entry: usize, i: usize| {
        let (outer, inner) = (&lines[entry], &lines[i]);
        let (outer, inner) = (
            &text[outer.start..outer.indent],
            &text[inner.start..inner.indent],
        );
        inner.len() > outer.len() && inner.starts_with(outer)
    };
    // `owner`: the outermost Entry whose value is empty, an opener or a block header,
    // or line that ends in `:`. A blank run before a line deeper than it does not end
    // the paragraph (the residue view must not split such a block).
    let (mut first, mut blank, mut near, mut owner) = (None, None::<usize>, None, None);
    let (mut entries, mut sep0, mut prose, mut stack) = (0, 0, false, Vec::new());
    for i in 0..lines.len() {
        if lines[i].joined {
            prose |= lines[i].taint;
            continue;
        }
        if lines[i].shape == Shape::Blank {
            if first.is_some() {
                blank.get_or_insert(i);
            }
            continue;
        }
        let mut child = lines[i].shape == Shape::Other
            && near.is_some_and(|entry: usize| {
                matches!(lines[entry].shape, Shape::Entry(_, kind, _) if kind != Kind::Inline)
                    && deeper(&lines, entry, i)
            });
        if let (Some(from), Some(gap)) = (first, blank.take()) {
            if !child && !owner.is_some_and(|entry| deeper(&lines, entry, i)) {
                close(&mut lines, from, gap - 1, !prose && entries >= 2);
                first = None;
            }
        }
        if first.is_none() {
            (first, near, owner, entries, prose, child) = (Some(i), None, None, 0, false, false);
            stack.clear();
        }
        // The indent stack: a key block's end that dedents to no level is unsafe.
        let indent = &text[lines[i].start..lines[i].indent];
        let mut popped = false;
        while stack
            .last()
            .is_some_and(|top: &&str| deeper_than(top, indent))
        {
            (_, popped) = (stack.pop(), true);
        }
        prose |= lines[i].taint || lines[i].ends_block && popped && stack.last() != Some(&indent);
        if stack.last().is_none_or(|top| deeper_than(indent, top)) {
            stack.push(indent);
        }
        lines[i].child = child;
        let body = text[lines[i].start..lines[i].end].trim_end();
        let inner = owner.is_some_and(|entry| deeper(&lines, entry, i));
        if (matches!(lines[i].shape, Shape::Entry(_, kind, _) if kind != Kind::Inline)
            || body.ends_with([':', '：']))
            && !inner
        {
            owner = Some(i);
        } else if matches!(lines[i].shape, Shape::Entry(..)) && !inner {
            owner = None;
        }
        match lines[i].shape {
            Shape::Entry(sep, ..) => {
                sep0 = if entries == 0 { sep } else { sep0 };
                prose |= sep != sep0;
                entries += 1;
                near = Some(i);
            }
            Shape::Structure => {}
            _ => prose |= !child,
        }
    }
    if let Some(from) = first {
        let last = blank.map_or(lines.len() - 1, |gap| gap - 1);
        close(&mut lines, from, last, !prose && entries >= 2);
    }
    (lines, pairs)
}
