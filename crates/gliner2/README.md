# auxesis-gliner2

Zero-shot entity extraction with [GLiNER2](https://github.com/fastino-ai/GLiNER2)
over ONNX Runtime. You name the labels; you get back the spans of the text that
match them, with byte offsets, a label and a score.

## Install

```toml
[dependencies]
auxesis-gliner2 = "0.1.8"
```

The package is `auxesis-gliner2`; the library name stays `gliner2_rs`.

```rust,no_run
use gliner2_rs::{Gliner2, Options};

let model = Gliner2::load("models/gliner2-privacy-filter-PII-multi", &Options::default())
    .expect("load the exported model");
for entity in model
    .extract("Mara Ellison, mara@example.com", &["person", "email"], 0.5)
    .expect("run the graph")
{
    println!("{} {}..{} {:.2}", entity.label, entity.start, entity.end, entity.score);
}
```

`Gliner2::load` reads `model.onnx` and `tokenizer.json` from a directory;
`load_paths` takes the two files explicitly. ONNX Runtime 1.20 is loaded at run
time (`Options::ort_dylib` or `ORT_DYLIB_PATH`), so building downloads nothing
and the crate ships no model. The graph used by Auxesis is an Apache-2.0 export
of `fastino/gliner2-privacy-filter-PII-multi`; the export and parity scripts
are in the repository.

## Licence

PolyForm-Noncommercial-1.0.0, the workspace licence. The model is a separate
work under its own licence (above).
