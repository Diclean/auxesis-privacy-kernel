use super::hidden;

#[test]
fn each_form_hides_only_its_value() {
    assert_eq!(hidden("csrftoken=Zx81mNq02LpWv7Ks"), ["Zx81mNq02LpWv7Ks"]);
    assert_eq!(
        hidden("Set-Cookie: a=k2Lp9xQe7Rv3Wm8T; Path=/; Expires=Wed, 21 Oct 2026"),
        ["k2Lp9xQe7Rv3Wm8T"]
    );
    assert_eq!(hidden("PIN\r\n4821"), ["4821"]);
    assert_eq!(hidden("id,\"pwd\"\n1,\"a,b,c9\""), ["\"a,b,c9\"", "a,b,c9"]);
    assert_eq!(hidden("akiaiosfodnn7exampleok"), ["akiaiosfodnn7exampleok"]);
    assert_eq!(
        hidden("Re: your Passphrase (violet tractor humming seventy)"),
        ["violet tractor humming seventy"]
    );
    assert_eq!(
        hidden("Passphrase: cerise lune papier"),
        ["cerise lune papier"]
    );
    assert_eq!(
        hidden("Password\nChange it every month."),
        ["Change it every month."]
    );
    assert_eq!(hidden("Passphrase: words!"), ["words!"]);
    assert_eq!(hidden("asiabcdfghjklmnpqrstok"), ["asiabcdfghjklmnpqrstok"]);
}

#[test]
fn lookalikes_stay_clear() {
    for text in [
        "session=short",
        "Password\nChange it every month and never share it with anyone at all, not even the people at the desk.",
        "Passphrase: pick four random words and keep them safe.",
        "Passphrase protection is on for every account.",
        "| token | count |\n|---|---|\n| | 3 |",
        "asianfusionrestaurants",
        "xakiaiosfodnn7example",
        "id,name\n1,2",
        "Mot de passe oublié ?",
    ] {
        assert_eq!(hidden(text), Vec::<&str>::new(), "{text:?}");
    }
}
