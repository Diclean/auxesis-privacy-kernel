use super::masked;

use super::super::blood::MAX_ROWS;

#[test]
fn a_blood_column_reads_max_rows_and_no_more() {
    let mut text = String::from("id,\"x, y\",blood_type\n");
    for row in 1..=MAX_ROWS + 1 {
        text.push_str(&format!("{row},\"a,\"\"b\"\"\",O+\n"));
    }
    let cells = masked(&text);
    assert_eq!(cells.len(), MAX_ROWS);
    assert!(cells.iter().all(|cell| *cell == "O+"));
    assert!(text.ends_with(&format!("{},\"a,\"\"b\"\"\",O+\n", MAX_ROWS + 1)));
}
