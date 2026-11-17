use super::LoadConfigField;

/// The fields tile each layout without a gap or an overlap, and the last field ends at the
/// known size of the layout.
#[test]
fn fields_tile_both_layouts() {
    for (is_64bit, known_end) in [(false, 0xc4), (true, 0x148)] {
        let mut fields = LoadConfigField::ALL;
        fields.sort_by_key(|field| field.offset(is_64bit));
        let mut end = 0;
        for field in fields {
            assert_eq!(field.offset(is_64bit), end, "{field:?}");
            end = field.end(is_64bit);
        }
        assert_eq!(end, known_end);
    }
}
