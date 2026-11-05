// KV02-SECRETS cases, read by `secret_forms_recall.rs`. Every value is
// invented. Key bodies come from a seeded xorshift and are joined to their
// prefix at run time, so no whole key is written in this file; the cue values
// carry obviously fake words and digits.

/// A positive case: its form, its text, and the values of which no 6-character
/// run may stay readable in the gate's output.
pub type Case = (&'static str, String, Vec<String>);

const ALNUM: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const KEY: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
const HEX: &str = "0123456789abcdef";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const LOWER: &str = "abcdefghijklmnopqrstuvwxyz0123456789";
const B64: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B32: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const DIGITS: &str = "0123456789";
const CRYPT: &str = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const AZURE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_~.-";

/// `n` invented characters of `alphabet`, the same on every machine for `seed`.
fn fake(alphabet: &str, n: usize, seed: u64) -> String {
    let chars: Vec<char> = alphabet.chars().collect();
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..n)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            chars[(state % chars.len() as u64) as usize]
        })
        .collect()
}

/// An invented UUID.
fn uuid(seed: u64) -> String {
    let h = fake(HEX, 32, seed);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

/// One value set into `frame` at its first `{}`.
fn c(form: &'static str, frame: &str, value: &str) -> Case {
    (
        form,
        frame.replacen("{}", value, 1),
        vec![value.to_string()],
    )
}

/// A text and the values inside it.
fn m(form: &'static str, text: String, values: Vec<String>) -> Case {
    (form, text, values)
}

/// Invented word lists of seed-phrase length (not a real wallet).
const WORDS_A: &str =
    "orbit candle pepper silver tunnel violet harbor mango window quartz lemon tiger";
const WORDS_B: &str =
    "canyon ribbon walnut meadow saddle frozen gadget lantern pistol rocket sunset velvet";
const WORDS_C: &str =
    "anchor bamboo cactus dolphin engine falcon glacier hammer island jacket kettle ladder";
const WORDS_D: &str =
    "magnet napkin oyster parrot quiver rabbit salmon teapot uncle valley wizard yellow";
const WORDS_E: &str =
    "zebra copper basket button cherry donkey eagle feather garlic helmet insect jungle";
const WORDS_F: &str =
    "kitten lobster marble needle olive panda puzzle radar shadow spider stable thunder";
const WORDS_G: &str =
    "tomato tongue trophy turtle umbrella vapor vessel wagon walrus whisper willow wrist";

/// Every positive case, one per line.
#[rustfmt::skip]
pub fn positives() -> Vec<Case> {
    let k = fake;
    let pem_a = [
        format!("b3BlbnNzaC1rZXktdjEAAAAA{}", k(B64, 46, 501)),
        k(B64, 70, 502),
        format!("{}=", k(B64, 19, 503)),
    ];
    let pem_b = [
        format!("MIIEpAIBAAKCAQEA{}", k(B64, 48, 504)),
        k(B64, 64, 505),
        format!("{}==", k(B64, 30, 506)),
    ];
    let pem_c = [format!("MHcCAQEEI{}", k(B64, 55, 507)), k(B64, 40, 508)];
    let pem_d = [format!("P2/56wAAA{}", k(B64, 55, 509)), k(B64, 64, 510)];
    let pem_e = [format!("MIIEowIBAAKCAQEA{}", k(B64, 48, 511)), k(B64, 64, 512)];
    let pem_f = [
        format!("b3BlbnNzaC1rZXktdjEAAAAA{}", k(B64, 46, 513)),
        k(B64, 70, 514),
        k(B64, 70, 515),
        k(B64, 30, 516),
    ];
    let pem_g = [
        format!("MIIEvQIBADANBgkqhkiG9w0BAQEFAASC{}", k(B64, 32, 517)),
        k(B64, 64, 518),
        k(B64, 64, 519),
        format!("{}==", k(B64, 20, 520)),
    ];
    let pem_h = [
        format!("MIIEvgIBADANBgkqhkiG9w0BAQEFAASC{}", k(B64, 44, 521)),
        k(B64, 76, 522),
        k(B64, 76, 523),
        k(B64, 10, 524),
    ];
    let pem_i = [format!("MIIEvQIBADAN{}", k(B64, 52, 525)), k(B64, 64, 526)];
    let pem_j = [format!("lQOYBF{}", k(B64, 58, 527)), k(B64, 64, 528)];
    let pem_k = k(B64, 44, 529);
    let pem_l = [
        format!("MIIEvAIBADANBgkqhkiG9w0BAQEFAASC{}", k(B64, 44, 921)),
        k(B64, 76, 922),
        k(B64, 76, 923),
        format!("{}=", k(B64, 39, 924)),
    ];
    vec![
        // New issuer key shapes, in neutral frames (no cue word).
        c("vendor-new", "tracing uses {} today", &format!("lsv2_pt_{}_{}", k(HEX, 32, 101), k(HEX, 10, 102))),
        c("vendor-new", "{}", &format!("pcsk_{}_{}", k(ALNUM, 6, 103), k(ALNUM, 63, 104))),
        c("vendor-new", "Figma: {}", &format!("figd_{}EXAMPLE{}", k(KEY, 13, 105), k(KEY, 20, 106))),
        c("vendor-new", "postman {} ok", &format!("PMAK-{}-{}", k(HEX, 24, 107), k(HEX, 34, 108))),
        c("vendor-new", "TFC {}", &format!("{}.atlasv1.{}", k(ALNUM, 14, 109), k(ALNUM, 67, 110))),
        c("vendor-new", "doppler run with {}", &format!("dp.pt.{}EXAMPLE{}", k(ALNUM, 20, 111), k(ALNUM, 16, 112))),
        c("vendor-new", "(pulumi {})", &format!("pul-{}", k(HEX, 40, 113))),
        c("vendor-new", "netlify deploy --auth {}", &format!("nfp_{}EXAMPLE{}", k(ALNUM, 15, 114), k(ALNUM, 14, 115))),
        c("vendor-new", "render: {}", &format!("rnd_{}EXAMPLE{}", k(ALNUM, 13, 116), k(ALNUM, 12, 117))),
        c("vendor-new", "airtable {}", &format!("pat{}.{}", k(ALNUM, 14, 118), k(HEX, 64, 119))),
        c("vendor-new", "notion integration {}", &format!("secret_{}EXAMPLE{}", k(ALNUM, 18, 120), k(ALNUM, 18, 121))),
        c("vendor-new", "contentful {}", &format!("CFPAT-{}EXAMPLE{}", k(KEY, 18, 122), k(KEY, 18, 123))),
        c("vendor-new", "sentry-cli uses {}", &format!("sntryu_{}", k(HEX, 64, 124))),
        c("vendor-new", "{} for the workspace", &format!("dapi{}", k(HEX, 32, 125))),
        c("vendor-new", "sonar {}", &format!("squ_{}", k(HEX, 40, 126))),
        c("vendor-new", "bitbucket app {}", &format!("ATBB{}EXAMPLE{}", k(ALNUM, 13, 127), k(ALNUM, 12, 128))),
        c("vendor-new", "circleci {}", &format!("CCIPAT_{}_{}", k(ALNUM, 22, 129), k(HEX, 40, 130))),
        c("vendor-new", "buildkite {}", &format!("bkua_{}", k(HEX, 40, 131))),
        c("vendor-new", "dynatrace {}", &format!("dt0c01.{}.{}", k(UPPER, 24, 132), k(UPPER, 64, 133))),
        c("vendor-new", "vault batch {}", &format!("hvb.{}", k(KEY, 92, 134))),
        c("vendor-new", "slack refresh {}", &format!("xoxe-1-{}", k(ALNUM, 80, 135))),
        c("vendor-new", "slack client {}", &format!("xoxc-{}-{}-{}-{}", k(DIGITS, 10, 136), k(DIGITS, 13, 137), k(DIGITS, 13, 138), k(HEX, 64, 139))),
        c("vendor-new", "brevo {}", &format!("xkeysib-{}-{}", k(HEX, 64, 140), k(ALNUM, 16, 141))),
        c("vendor-new", "mailchimp {}", &format!("{}-us21", k(HEX, 32, 142))),
        c("vendor-new", "braintree {}", &format!("access_token$production${}${}", k(LOWER, 16, 143), k(HEX, 32, 144))),
        c("vendor-new", "square {}", &format!("sq0atp-{}", k(KEY, 22, 145))),
        c("vendor-new", "square oauth {}", &format!("sq0csp-{}", k(KEY, 43, 146))),
        c("vendor-new", "plaid item {}", &format!("access-production-{}", uuid(147))),
        c("vendor-new", "aliyun {}", &format!("LTAI{}", k(ALNUM, 20, 148))),
        c("vendor-new", "tencent cloud {}", &format!("AKID{}", k(ALNUM, 32, 149))),
        c("vendor-new", "azure app {}", &format!("{}8Q~{}", k(ALNUM, 3, 150), k(AZURE, 34, 151))),
        c("vendor-new", "1Password: {}", &format!("A3-EXAMPL-{}-{}-{}-{}-{}", k(UPPER, 6, 152), k(UPPER, 5, 153), k(UPPER, 5, 154), k(UPPER, 5, 155), k(UPPER, 5, 156))),
        c("vendor-new", "gem push with {}", &format!("rubygems_{}", k(HEX, 48, 157))),
        c("vendor-new", "nuget {}", &format!("oy2{}", k(LOWER, 43, 158))),
        c("vendor-new", "artifactory {}", &format!("AKCp{}", k(ALNUM, 69, 159))),
        c("vendor-new", "hf org {}", &format!("api_org_{}EXAMPLE{}", k(ALNUM, 14, 160), k(ALNUM, 13, 161))),
        c("vendor-new", "shopify {}", &format!("shppa_{}", k(HEX, 32, 162))),
        c("vendor-new", "gitlab job {}", &format!("glcbt-{}", k(ALNUM, 24, 163))),
        c("vendor-new", "gitlab app {}", &format!("gloas-{}", k(HEX, 64, 164))),
        c("vendor-new", "feed {}", &format!("glft-{}", k(KEY, 20, 165))),
        c("vendor-new", "runner {}", &format!("GR1348941{}", k(KEY, 20, 166))),
        c("vendor-new", "wallet {}", &format!("xprv9s21ZrQH143K{}", k(B58, 95, 167))),
        c("vendor-new", "post to https://hooks.slack.com/services/{}", &format!("T{}/B{}/{}", k(UPPER, 10, 168), k(UPPER, 10, 169), k(ALNUM, 24, 170))),
        c("vendor-new", "webhook https://discord.com/api/webhooks/{}", &format!("{}/{}", k(DIGITS, 18, 171), k(KEY, 68, 172))),
        c("vendor-new", "LangSmith service {}", &format!("lsv2_sk_{}_{}", k(HEX, 32, 173), k(HEX, 10, 174))),
        // Issuer shapes the kernel reads already: they must stay hidden.
        c("vendor-old", "{}", &format!("ghp_{}", k(ALNUM, 36, 201))),
        m("vendor-old", format!("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = {}", k(B64, 40, 202)), vec!["AKIAIOSFODNN7EXAMPLE".into(), k(B64, 40, 202)]),
        c("vendor-old", "key {}", &format!("sk-proj-{}", k(ALNUM, 48, 203))),
        c("vendor-old", "{}", &format!("xoxb-{}-{}-{}", k(DIGITS, 12, 204), k(DIGITS, 13, 205), k(ALNUM, 24, 206))),
        c("vendor-old", "maps {}", &format!("AIzaSy{}", k(KEY, 33, 207))),
        c("vendor-old", "jwt {}", &format!("eyJhbGciOiJIUzI1NiJ9.{}.{}", k(KEY, 40, 208), k(KEY, 43, 209))),
        c("vendor-old", "{}", &format!("glpat-{}", k(KEY, 20, 210))),
        c("vendor-old", "npm {}", &format!("npm_{}", k(ALNUM, 36, 211))),
        c("vendor-old", "{}", &format!("SG.{}.{}", k(KEY, 22, 212), k(KEY, 43, 213))),
        c("vendor-old", "vault {}", &format!("hvs.{}", k(KEY, 90, 214))),
        c("vendor-old", "stripe {}", &format!("sk_{}_{}", "live", k(ALNUM, 24, 215))),
        c("vendor-old", "{}", &format!("AGE-SECRET-KEY-1{}", k(UPPER, 58, 216))),
        // English cues.
        c("cue-en", "password: {}", "Hunter22!x"),
        c("cue-en", "The password is {}, keep it safe.", "Maple-Leaf-77"),
        c("cue-en", "pwd = {}", "Tr0ub4dor&3"),
        c("cue-en", "Your temporary password: {}", "Qx7!mN2pLk"),
        c("cue-en", "login alice / pass {}", "Zebra#4471"),
        c("cue-en", "My PIN is {}.", "7314"),
        c("cue-en", "Your verification code: {}", "482913"),
        c("cue-en", "API token: {}", "tok9f8e7d6c5b4a3210EXAMPLE"),
        c("cue-en", "the client secret is {}", &k(HEX, 32, 301)),
        c("cue-en", "The VPN password for the office is {}.", "Correct-Horse-42"),
        c("cue-en", "creds: alice / {}", "Hunter22!c"),
        c("cue-en", "Wi-Fi: CafeNet / password: {}", "Latte2026!x"),
        c("cue-en", "SSH key passphrase: {}", "purple monkey dishwasher 42"),
        c("cue-en", "username alice password {}", "Velvet9Thunder"),
        c("cue-en", "the alarm code is {}", "5091"),
        m("cue-en", "Here are my backup codes: 4821-7731 9902-1184 3376-5520".into(), vec!["4821-7731".into(), "9902-1184".into(), "3376-5520".into()]),
        c("cue-en", "your one-time passcode is {}", "739104"),
        c("cue-en", "pw: {}", "Hunter22pw"),
        c("cue-en", "My new password will be {}", "Hunter22!n"),
        c("cue-en", "Password (case-sensitive): {}", "Hunter22!s"),
        c("cue-en", "the wifi key is {}", "Latte2026kk"),
        c("cue-en", "Password: {}", "correct horse battery staple"),
        c("cue-en", "secret: {}", "Mx9!pQ2#rT"),
        // French cues.
        c("cue-fr", "mot de passe : {}", "Soleil2026!"),
        c("cue-fr", "Le mot de passe est {}.", "Soleil#Vert26"),
        c("cue-fr", "le mot de passe c'est {}", "Pluie2026!x"),
        c("cue-fr", "mdp c'est {} pour l'instant", "Neige2026!x"),
        c("cue-fr", "Mot de passe provisoire : {}", "Qx7!mN2pLf"),
        c("cue-fr", "Code confidentiel : {}", "4821"),
        c("cue-fr", "Voici mes identifiants : alice / {}", "Brume#2026"),
        c("cue-fr", "clé API : {}", "cle9f8e7d6c5b4aEXAMPLE"),
        c("cue-fr", "Le code d'accès est {}", "7731"),
        c("cue-fr", "jeton d'accès : {}", "jet9f8e7d6c5b4aEXAMPLE"),
        c("cue-fr", "Code wifi : {}", "Latte2026!f"),
        c("cue-fr", "nouveau mot de passe = {}", "Pluie#Fine88"),
        c("cue-fr", "MDP: {}", "Pluie#Fine89x"),
        c("cue-fr", "le mot de passe du portail est {}", "Givre#2026"),
        c("cue-fr", "mon code PIN est {}", "7315"),
        c("cue-fr", "code de vérification : {}", "482914"),
        c("cue-fr", "phrase secrète : {}", "chat lune vélo pomme"),
        c("cue-fr", "Votre code secret : {}", "5521"),
        c("cue-fr", "Le mot de passe Wi-Fi est {}", "Latte2026!w"),
        c("cue-fr", "identifiant : alice, mot de passe : {}", "Brume#2027"),
        c("cue-fr", "Mot de passe : « {} »", "Soleil2027!"),
        c("cue-fr", "Le mot de passe pour le wifi est {}", "Pluie#2026wf"),
        // Afrikaans cues.
        c("cue-af", "wagwoord: {}", "Somer2026!x"),
        c("cue-af", "Die wagwoord is {}.", "Somer#Wind26"),
        c("cue-af", "My wagwoord vir die wifi is {}", "Somer2027!x"),
        c("cue-af", "Wagwoord vir e-pos: {}", "Somer2028!x"),
        c("cue-af", "PIN-kode: {}", "7316"),
        c("cue-af", "toegangskode: {}", "7732"),
        c("cue-af", "API-sleutel: {}", "ak9f8e7d6c5b4aEXAMPLE"),
        c("cue-af", "geheime sleutel: {}", "gs9f8e7d6c5b4aEXAMPLE"),
        c("cue-af", "Jou eenmalige PIN is {}", "482915"),
        c("cue-af", "toegangsteken: {}", "tt9f8e7d6c5b4aEXAMPLE"),
        c("cue-af", "Die wifi-wagwoord is {}", "Somer2029!x"),
        c("cue-af", "nuwe wagwoord = {}", "Winter#2026x"),
        c("cue-af", "Gebruikersnaam: alice\nWagwoord: {}", "Herfs#2026x"),
        // Hungarian cues.
        c("cue-hu", "jelszó: {}", "Tavasz2026!"),
        c("cue-hu", "Jelszó: {}", "Tavasz#Szel26"),
        c("cue-hu", "A jelszavam: {}", "Nyar2026!x"),
        c("cue-hu", "Az új jelszó {}", "Osz#2026xy"),
        c("cue-hu", "A wifi jelszó: {}", "Tavasz2027!x"),
        c("cue-hu", "Belépés a következő jelszóval: {}", "Tel#2026xy"),
        c("cue-hu", "A fiók jelszava: {}", "Tavasz2028!x"),
        c("cue-hu", "PIN-kód: {}", "7317"),
        c("cue-hu", "API-kulcs: {}", "hk9f8e7d6c5b4aEXAMPLE"),
        c("cue-hu", "titkos kulcs: {}", "tk9f8e7d6c5b4aEXAMPLE"),
        c("cue-hu", "hozzáférési token: {}", "ht9f8e7d6c5b4aEXAMPLE"),
        c("cue-hu", "ellenőrző kód: {}", "482916"),
        c("cue-hu", "jelszó = {}", "Tavasz2029!"),
        c("cue-hu", "Felhasználónév: alice, jelszó: {}", "Nyar#2027x"),
        // Slovene cues.
        c("cue-sl", "geslo: {}", "Pomlad2026!"),
        c("cue-sl", "Geslo je {}.", "Pomlad#Veter26"),
        c("cue-sl", "Geslo za Wi-Fi je {}", "Pomlad2027!x"),
        c("cue-sl", "moje geslo: {}", "Poletje2026!"),
        c("cue-sl", "Novo geslo: {}", "Jesen#2026x"),
        c("cue-sl", "PIN koda: {}", "7318"),
        c("cue-sl", "API ključ: {}", "sk9f8e7d6c5b4aEXAMPLE"),
        c("cue-sl", "dostopni žeton: {}", "dz9f8e7d6c5b4aEXAMPLE"),
        c("cue-sl", "varnostna koda: {}", "482917"),
        c("cue-sl", "geslo za e-pošto: {}", "Zima#2026xy"),
        c("cue-sl", "Uporabniško ime: alice, geslo: {}", "Pomlad2028!"),
        c("cue-sl", "geslo = {}", "Pomlad2029!"),
        c("cue-sl", "Geslo za domači wifi je {}", "Pomlad#2030"),
        // Chinese cues.
        c("cue-zh", "密码：{}", "Spring2026!"),
        c("cue-zh", "密码是{}", "Spring#Rain26"),
        c("cue-zh", "我的密码是 {}", "Summer2026!x"),
        c("cue-zh", "初始密码为{}", "Autumn2026!x"),
        c("cue-zh", "WiFi密码：{}", "Winter2026!x"),
        c("cue-zh", "登录密码 {}", "Login2026!x"),
        c("cue-zh", "验证码：{}", "482918"),
        c("cue-zh", "支付密码是{}", "731455"),
        c("cue-zh", "口令：{}", "Kouling2026!"),
        c("cue-zh", "API密钥：{}", "zk9f8e7d6c5b4aEXAMPLE"),
        c("cue-zh", "密钥是{}", "mk9f8e7d6c5b4aEXAMPLE"),
        c("cue-zh", "私钥：{}", "pk9f8e7d6c5b4aEXAMPLE"),
        c("cue-zh", "访问令牌：{}", "lp9f8e7d6c5b4aEXAMPLE"),
        c("cue-zh", "账号：alice 密码：{}", "Zhanghu2026!"),
        c("cue-zh", "密码改成了{}", "Gaile2026!x"),
        c("cue-zh", "WiFi密码 {}", "Wifi2026!zz"),
        // .env and config lines.
        c("env", "DB_PASSWORD={}", "Hunter22!e"),
        c("env", "export GITHUB_TOKEN={}", &k(ALNUM, 40, 401)),
        c("env", "PGPASSWORD={} psql -h db.internal -U app", "Hunter22pg"),
        c("env", "MYSQL_ROOT_PASSWORD: \"{}\"", "Hunter22!r"),
        c("env", "JWT_SECRET={}", &k(HEX, 64, 402)),
        c("env", "MNEMONIC=\"{}\"", WORDS_A),
        c("env", "AZURE_STORAGE_CONNECTION_STRING=DefaultEndpointsProtocol=https;AccountName=exampleacct;AccountKey={};EndpointSuffix=core.windows.net", &format!("{}==", k(B64, 86, 403))),
        c("env", "WIFI_PSK={}", "Latte2026!p"),
        c("env", "dbpassword={}", "Hunter22db"),
        c("env", "adminPassword: {}", "Hunter22ad"),
        c("env", "CREDS=alice:{}", "Hunter22cr"),
        c("env", "[client]\nuser = app\npassword = {}", "Hunter22my"),
        c("env", "network={\n  ssid=\"CafeNet\"\n  psk=\"{}\"\n}", "Latte2026!s"),
        c("env", "[Peer]\nPresharedKey = {}", &format!("{}=", k(B64, 43, 404))),
        c("env", "SMTP_PASS={}", "Hunter22sm"),
        c("env", "SECRET_KEY_BASE={}", &k(HEX, 128, 405)),
        c("env", "rootpassword: {}", "Hunter22rt"),
        c("env", "API_TOKEN='{}'", "tok9f8e7d6c5b4a3211EXAMPLE"),
        c("env", "SESSION_SECRET=\"{}\"", &k(ALNUM, 32, 406)),
        c("env", "GPG_PASSPHRASE={}", "correct horse battery 42"),
        c("env", "export PGPASSWORD='{}'", "Hunter22pq"),
        c("env", "REDISPASSWORD={}", "Hunter22rp"),
        c("env", "clientsecret: {}", &k(HEX, 32, 407)),
        // Connection strings and URLs.
        c("dsn", "postgres://app:{}@db.example.com:5432/app", "Hunter22ds"),
        c("dsn", "mongodb+srv://admin:{}@cluster0.example.net/test", "Hunter22mo"),
        c("dsn", "amqp://guest:{}@mq.internal:5672/", "Rabbit2026x"),
        c("dsn", "Server=tcp:db.example.com,1433;Database=app;User ID=app;Password={};", "Hunter22!q"),
        c("dsn", "jdbc:postgresql://db:5432/app?user=app&password={}", "Hunter22jd"),
        c("dsn", "https://alice:{}@git.example.com/repo.git", "Hunter22gt"),
        c("dsn", "smtp://mailer:{}@smtp.example.com:587", "Hunter22st"),
        c("dsn", "Driver={ODBC};Server=x;Uid=app;Pwd={};", "Hunter22od"),
        c("dsn", "Data Source=db;Initial Catalog=x;User Id=app;Password={}", "Hunter22ss"),
        c("dsn", "https://exampleacct.blob.core.windows.net/c/f.txt?sv=2022-11-02&ss=b&srt=o&sp=r&se=2026-12-31T00:00:00Z&sig={}", &format!("{}%3D", k(B64, 43, 451))),
        c("dsn", "https://bucket.s3.amazonaws.com/f.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=3600&X-Amz-Signature={}", &k(HEX, 64, 452)),
        c("dsn", "redis://:{}@cache.internal:6379/0", "Hunter22rd"),
        // Authorization and API-key headers.
        c("auth", "Authorization: Bearer {}", &k(ALNUM, 40, 601)),
        c("auth", "Authorization: Basic {}", &format!("{}==", k(B64, 26, 602))),
        c("auth", "Authorization: Token {}", &k(HEX, 40, 603)),
        c("auth", "{\"Authorization\": \"Bearer {}\"}", &k(ALNUM, 40, 604)),
        c("auth", "headers = {'Authorization': 'Basic {}'}", &format!("{}=", k(B64, 31, 605))),
        c("auth", "Authorization: SSWS {}", &format!("00{}", k(KEY, 40, 606))),
        c("auth", "Authorization: DeepL-Auth-Key {}", &format!("{}:fx", uuid(607))),
        c("auth", "X-API-Key: {}", &k(ALNUM, 32, 608)),
        c("auth", "api-key: {}", &k(HEX, 32, 609)),
        c("auth", "Ocp-Apim-Subscription-Key: {}", &k(HEX, 32, 610)),
        c("auth", "PRIVATE-TOKEN: {}", &k(KEY, 20, 611)),
        c("auth", "Cookie: sessionid={}", &k(ALNUM, 32, 612)),
        c("auth", "Proxy-Authorization: Basic {}", &format!("{}==", k(B64, 22, 613))),
        c("auth", "curl -H \"Authorization: Token {}\" https://api.example.com/v1/items", &k(HEX, 40, 614)),
        c("auth", "Authorization: ApiKey {}", &k(ALNUM, 40, 615)),
        c("auth", "authorization: token {}", &k(HEX, 40, 616)),
        c("auth", "X-Auth-Token: {}", &k(ALNUM, 32, 617)),
        // Command lines.
        c("cli", "curl -u alice:{} https://api.example.com/v1/me", "Hunter22cu"),
        c("cli", "curl --user \"bob:{}\" https://api.example.com", "Hunter22cv"),
        c("cli", "docker login -u alice -p {} registry.example.com", "Hunter22dk"),
        c("cli", "sshpass -p '{}' ssh alice@build-host", "Hunter22sp"),
        c("cli", "mysql -u root -p{} appdb", "Hunter22my2"),
        c("cli", "wget --http-password={} https://files.example.com/x", "Hunter22wg"),
        c("cli", "my-tool --db-password {} --verbose", "Hunter22db2"),
        c("cli", "kubectl create secret generic db --from-literal=password={}", "Hunter22kc"),
        c("cli", "htpasswd -b users.htpasswd alice {}", "Hunter22ht"),
        c("cli", "openssl pkcs12 -export -passout pass:{}", "Hunter22os"),
        c("cli", "psql postgresql://app:{}@db.example.com/app", "Hunter22pq2"),
        c("cli", "git clone https://oauth2:{}@gitlab.com/x/y.git", &format!("glpat-{}", k(KEY, 20, 701))),
        c("cli", "redis-cli -a {} -h cache.internal", "Hunter22rc"),
        // Private key blocks and bodies.
        m("pem", format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n{}\n{}\n-----END OPENSSH PRIVATE KEY-----", pem_a[0], pem_a[1], pem_a[2]), vec![pem_a[0].clone(), pem_a[1].clone(), pem_a[2].clone()]),
        m("pem", format!("-----BEGIN RSA PRIVATE KEY-----\n{}\n{}\n{}\n-----END RSA PRIVATE KEY-----", pem_b[0], pem_b[1], pem_b[2]), vec![pem_b[0].clone(), pem_b[1].clone(), pem_b[2].clone()]),
        m("pem", format!("-----BEGIN EC PRIVATE KEY-----\n{}\n{}\n-----END EC PRIVATE KEY-----", pem_c[0], pem_c[1]), vec![pem_c[0].clone(), pem_c[1].clone()]),
        m("pem", format!("---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nComment: \"rsa-key-20261105\"\n{}\n{}\n---- END SSH2 ENCRYPTED PRIVATE KEY ----", pem_d[0], pem_d[1]), vec![pem_d[0].clone(), pem_d[1].clone()]),
        m("pem", format!("----BEGIN RSA PRIVATE KEY----\n{}\n{}\n----END RSA PRIVATE KEY----", pem_e[0], pem_e[1]), vec![pem_e[0].clone(), pem_e[1].clone()]),
        m("pem", format!("here is the key body:\n{}\n{}\n{}\n{}", pem_f[0], pem_f[1], pem_f[2], pem_f[3]), vec![pem_f[0].clone(), pem_f[1].clone(), pem_f[2].clone(), pem_f[3].clone()]),
        m("pem", format!("{}\n{}\n{}\n{}", pem_g[0], pem_g[1], pem_g[2], pem_g[3]), vec![pem_g[0].clone(), pem_g[1].clone(), pem_g[2].clone(), pem_g[3].clone()]),
        m("pem", format!("{}\n{}\n{}\n{}", pem_h[0], pem_h[1], pem_h[2], pem_h[3]), vec![pem_h[0].clone(), pem_h[1].clone(), pem_h[2].clone(), pem_h[3].clone()]),
        m("pem", format!("{{\"type\": \"service_account\", \"private_key\": \"-----BEGIN PRIVATE KEY-----\\n{}\\n{}\\n-----END PRIVATE KEY-----\\n\"}}", pem_i[0], pem_i[1]), vec![pem_i[0].clone(), pem_i[1].clone()]),
        m("pem", format!("-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n{}\n{}\n=AbCd\n-----END PGP PRIVATE KEY BLOCK-----", pem_j[0], pem_j[1]), vec![pem_j[0].clone(), pem_j[1].clone()]),
        m("pem", format!("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: eddsa-key-20261105\nPublic-Lines: 1\nAAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLE\nPrivate-Lines: 1\n{}\nPrivate-MAC: {}", pem_k, k(HEX, 64, 530)), vec![pem_k.clone()]),
        // Seed phrases.
        c("seed", "seed phrase: {}", WORDS_B),
        c("seed", "My recovery phrase is {}", WORDS_C),
        c("seed", "mnemonic: {}", WORDS_D),
        c("seed", "助记词：{}", WORDS_E),
        m("seed", format!("Secret Recovery Phrase:\n{WORDS_F}"), vec![WORDS_F.into()]),
        c("seed", "phrase de récupération : {}", WORDS_G),
        // Other forms.
        c("misc", "WIFI:T:WPA;S:CafeNet;P:{};;", "Latte2026!q"),
        c("misc", "otpauth://totp/Example:alice?secret={}&issuer=Example", &k(B32, 32, 801)),
        c("misc", "alice:{}", &format!("$2b$12${}", k(CRYPT, 53, 802))),
        c("misc", "bob:{}", &format!("$apr1${}${}", k(CRYPT, 8, 803), k(CRYPT, 22, 804))),
        c("misc", "root:{}:19700:0:99999:7:::", &format!("$6${}${}", k(CRYPT, 16, 805), k(CRYPT, 86, 806))),
        c("misc", "hash = \"{}\"", &format!("$argon2id$v=19$m=65536,t=3,p=4${}${}", k(B64, 22, 807), k(B64, 43, 808))),
        c("misc", "telegram bot {}", &format!("{}:AA{}", k(DIGITS, 10, 809), k(KEY, 33, 810))),
        // KV02-SECRETS-2, from the peer seals of #92: V2 signatures (GCS, Alibaba
        // OSS, S3, CloudFront), versioned Discord webhooks, `htpasswd -n`, spaced
        // `mysql -p`, Digest responses, quoted and wrapped header credentials,
        // forms #92 added that must stay hidden, and URL userinfo edge cases.
        c("seal-2", "https://storage.googleapis.com/b/o?GoogleAccessId=svc@example.iam.gserviceaccount.com&Expires=1893456000&Signature={}", "abcdefghijklmnopqrstuvwxyz123456"),
        c("seal-2", "https://bucket.oss-cn-hangzhou.aliyuncs.com/f.pdf?Expires=2026-12-31&Signature={}", "abc123def456ghi789jkl012mno"),
        c("seal-2", "https://examplebucket.s3.amazonaws.com/r.pdf?AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Expires=1893456000&Signature={}", &format!("{}%2B{}%3D", k(ALNUM, 12, 901), k(ALNUM, 13, 902))),
        c("seal-2", "https://d111111abcdef8.cloudfront.net/v.mp4?Expires=1893456000&Signature={}&Key-Pair-Id=APKAEXAMPLE", &k(KEY, 120, 903)),
        c("seal-2", "post to https://discord.com/api/v10/webhooks/{}", &format!("123456789012345678/{}", k(KEY, 68, 905))),
        c("seal-2", "https://discordapp.com/api/v9/webhooks/{} (alerts)", &format!("{}/{}", k(DIGITS, 18, 904), k(KEY, 68, 906))),
        c("seal-2", "htpasswd -nb alice {}", "Hunter22ht2"),
        c("seal-2", "htpasswd -nbB alice {}", "s3cr3tpass"),
        c("seal-2", "htpasswd -nbBC 10 bob {} >> users.htpasswd", "Hunter22ht3"),
        c("seal-2", "echo $(htpasswd -n -b carol {}) | sed -e s/\\$/\\$\\$/g", "Hunter22ht4"),
        c("seal-2", "mysql -u root -p {} appdb", "Hunter22"),
        c("seal-2", "mysql -u root -p{} appdb", "Hunter22"),
        c("seal-2", "mysqldump -h db.internal -u app -p {} shop > shop.sql", "Hunter22md"),
        c("seal-2", "Authorization: Digest username=\"alice\", response=\"{}\"", &k(HEX, 32, 908)),
        c("seal-2", "Proxy-Authorization: Digest username=\"bob\", realm=\"api\", uri=\"/v1/items\", response=\"{}\", qop=auth", &k(HEX, 64, 909)),
        c("seal-2", "Authorization: Basic \"{}\"", &format!("{}==", k(B64, 22, 910))),
        c("seal-2", "Authorization: Bearer \"{}\"", &k(HEX, 40, 911)),
        c("seal-2", "Authorization: Bearer '{}'", &k(ALNUM, 40, 912)),
        m("seal-2", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345\nABCDEFGHIJKLMNOPQRST".into(), vec!["abcdefghijklmnopqrstuvwxyz012345".into(), "ABCDEFGHIJKLMNOPQRST".into()]),
        m("seal-2", format!("Authorization: Token {}\r\n  {}\r\nAccept: */*", k(HEX, 40, 913), k(HEX, 24, 914)), vec![k(HEX, 40, 913), k(HEX, 24, 914)]),
        m("seal-2", format!("Authorization: Bearer {}\n{}\n{}\nThanks for the help", k(ALNUM, 40, 915), k(ALNUM, 40, 916), k(ALNUM, 12, 917)), vec![k(ALNUM, 40, 915), k(ALNUM, 40, 916), k(ALNUM, 12, 917)]),
        c("seal-2", "refresh with {} then retry", &format!("xoxe-1-{}", k(ALNUM, 140, 918))),
        c("seal-2", "mailchimp {}", &format!("{}-us6", k(HEX, 32, 919))),
        c("seal-2", "MC key {} (list sync)", &format!("{}-us21", k(HEX, 32, 920))),
        m("seal-2", pem_l.join("\r\n"), pem_l.to_vec()),
        c("seal-2", "postgres://app:{}@db.example.com/app", "p@ssw0rd"),
        c("seal-2", "postgres://app:{}@db.example.com/app", "pa/ss"),
        c("seal-2", "DATABASE_URL=alice:{}@db.example.com", "hunter2"),
        c("seal-2", "docker login -u alice -p {}", "s3cret.pass"),
        // From the peer seals of #95: real values the look-alike rules of #95 left
        // in clear, then one real value beside the prose each remaining rule reads.
        c("seal-95", "PGPASSWORD={} for you", "correct horse battery staple"),
        c("seal-95", "PGPASSWORD = {} for prod", "a purple monkey dishwasher"),
        c("seal-95", "PGPASSWORD={} is rotated", "abcdefghijklmnopqrstuvwxyz"),
        c("seal-95", "PGPASSWORD={} is rotated now", "Supersecret"),
        c("seal-95", "accesstoken: {} is rotated", "mysecretvalue"),
        c("seal-95", "clientsecret: {} should be rotated", "abcdefghijklmnop"),
        c("seal-95", "authtoken: {} was changed", "monkeydishwasher"),
        c("seal-95", "dbpassword={} for four", "hunter two three"),
        c("seal-95", "topsecret: {} for", "hunter two three"),
        c("seal-95", "topsecret: {} for three", "hunter"),
        c("seal-95", "Authorization: Token {} here", "mysecretvalue"),
        c("seal-95", "Authorization: Token {} and", "abcdefghijklmnop"),
        c("seal-95", "Authorization: Token {} and", "abcd-efgh-ijkl-mnop-qrst-uvwx"),
        c("seal-95", "Authorization: Bot {} maintenance", "mysecretvalue"),
        c("seal-95", "Authorization: SSWS {} and", "mysecretvalue"),
        c("seal-95", "Authorization=Token {} and", "mysecretvalue"),
        c("seal-95", "Authorization: Token {} expires", "deadbeefdeadbeef"),
        c("seal-95", "SSWS {} expires", "abcdefghijklmnop"),
        c("seal-95", "https://files.example.com/f.pdf?sig={}", "deadbeefdeadbeef"),
        c("seal-95", "https://files.example.com/f.pdf?sig={}", "abcdefghijklmnop"),
        c("seal-95", "https://files.example.com/f.pdf?sig={}", "correct-horse-battery-staple"),
        c("seal-95", "https://files.example.com/f.pdf?sig={}", "my-shared-secret-2026"),
        c("seal-95", "docker login -p {}", "correct.pass"),
        c("seal-95", "docker login -p {}", "hunter.example.com"),
        c("seal-95", "docker login -p {}", "correct.horse.staple"),
        c("seal-95", "docker login -p {}", "a.b.co"),
        c("seal-95", "curl -u {}", "alice://supersecret"),
        c("seal-95", "htpasswd -nB alice {}", "batterystaple"),
        m("seal-95", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345\ndeadbeef".into(), vec!["abcdefghijklmnopqrstuvwxyz012345".into(), "deadbeef".into()]),
        c("seal-95", "apitoken: refresh {} before the meeting", "Zq8vR2xLmN4pT6wY"),
        c("seal-95", "accesstoken: rotated, the new one is {}", "hunter"),
        c("seal-95", "Authorization: Token {} refreshes happen every hour.", "Zq8vR2xLmN4pT6wY"),
        c("seal-95", "Docs: https://docs.example.com/sas?sig={} (your signature here)", "Zq8vR2xLmN4pT6wYb3"),
        c("seal-95", "docker login -p {} registry.example.com", "Zq8vR2xLmN4pT6wY"),
        c("seal-95", "curl -u {} https://example.com/v1/items", "alice:Zq8vR2xLmN4pT6wY"),
        c("seal-95", "htpasswd -nB alice {} > users.htpasswd", "Zq8vR2xLmN4pT6wY"),
    ]
}

/// Text that holds no secret: it must keep every byte, and no secret may be
/// counted in it, in either mode.
pub fn negatives() -> Vec<String> {
    let lines: &[&str] = &[
        // Words around secrets.
        "Forgot your password? Reset it from the sign-in page.",
        "The password must be at least 12 characters long.",
        "Use a password manager for every account.",
        "Enter the 6-digit code we sent you.",
        "Your verification code expires in 10 minutes.",
        "Generate a new token in the developer settings.",
        "Token economy explained in five minutes.",
        "The PIN pad on the door is broken.",
        "PIN codes are printed on the back of the card.",
        "Basic authentication requires HTTPS.",
        "The bearer token flow is described in RFC 6750.",
        "Plant the seed in spring and water it daily.",
        "Mnemonic devices help you remember lists.",
        "The tokenizer splits text into tokens.",
        "passwordless sign-in is enabled",
        // Git, hashes, IDs and order numbers.
        "commit 3f2a9c1b7e4d5f6a8b9c0d1e2f3a4b5c6d7e8f90",
        "a1b2c3d (HEAD -> main, origin/main) Fix typo in README",
        "Merge pull request #1234 from example/feature-login",
        "fix(auth): rotate tokens on logout (#482)",
        "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "md5 checksum 5d41402abc4b2a76b9719d911017c592 matches",
        "Order 3f2504e0-4f89-11d3-9a0c-0305e82c3301 shipped today.",
        "request 6f1c2d3e-4a5b-6c7d-8e9f-0a1b2c3d4e5f failed with 503",
        "Your order A1B2-C3D4-E5F6 has shipped.",
        "Invoice INV-2026-000123 is due on 30 November.",
        "Build 2026.11.05-rc1 passed all checks.",
        "Version v1.2.3-beta+exp.sha.5114f85 is live.",
        "a3f5c8e1d2b4a6c8e0f1a2b3c4d5e6f7-usage report",
        "Room A3-ROOM-101 is booked.",
        // Identifiers and words that start like a key prefix.
        "AbstractSingletonProxyFactoryBeanConfigurationManager",
        "max_connections_per_host_before_backoff_retry_limit = 8",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec dapibus.",
        "set rnd_seed_value_for_tests = 42",
        "Love you lots, xoxo-xoxo",
        "SKU SK-2026-RED-XL is back in stock.",
        "pip install scikit-learn sk-learn-extra",
        "Our key-value store handles 10k writes per second.",
        "The patient pattern matcher patched 14 files.",
        "xprv is the prefix of an extended private key.",
        "It costs $2 per item or $10 for six.",
        // Headers and command lines with no credential.
        "Authorization: pending manager approval",
        "Authorization: Basic auth is deprecated, use OAuth.",
        "Content-Type: application/json",
        "User-Agent: curl/8.4.0",
        "docker run -u 1000:1000 alpine id",
        "docker run -p 8080:80 nginx",
        "mkdir -p /tmp/build && cd /tmp/build",
        "ssh -p 2222 alice@build-host",
        "Use the -p flag to set the port.",
        "Run htpasswd -c users.htpasswd alice to add a user.",
        "export PATH=$HOME/bin:$PATH",
        "WIFI: free in the lobby, ask at the desk.",
        "Post alerts to the #ops channel with the Slack app.",
        "curl -u alice https://api.example.com/v1/me",
        "docker login registry.example.com",
        "echo $1$2$3 done",
        "The atlasv1 endpoint is deprecated.",
        // French.
        "Mot de passe oublié ?",
        "Le mot de passe doit contenir au moins 12 caractères.",
        "le mot de passe c'est important, ne le partagez pas.",
        "Changez votre mot de passe tous les trois mois.",
        "Le code wifi change chaque mois.",
        "Code confidentiel : voir la lettre de la banque.",
        "Le mot de passe c'est la clé, gardez-le.",
        // Hungarian.
        "Elfelejtette a jelszavát?",
        "A jelszó legalább 12 karakter legyen.",
        "A jelszó megváltozott tegnap este.",
        "jelszó módosítása a beállításokban",
        // Slovene.
        "Pozabljeno geslo?",
        "Geslo za Wi-Fi je na hladilniku.",
        "geslo za e-pošto: glej spodaj",
        // Afrikaans.
        "Kies 'n sterk wagwoord vir jou rekening.",
        "Wagwoord vir die wifi is op die yskas.",
        "Wagwoord vir e-pos: kyk onder",
        // Chinese.
        "忘记密码？",
        "请修改密码",
        "密码错误，请重试",
        "密码是什么？",
        "验证码已发送到你的手机",
        "初始密码为空",
        "验证码：请查看短信",
        // KV02-SECRETS-2: the false positives the peer seals of #92 found, and
        // look-alikes of the forms added after them.
        "Authorization: Token refreshes happen every hour.",
        "curl -u https://example.com/v1/items",
        "Docs: https://docs.example.com/sas?sig=your-signature-here",
        "https://files.example.com/f.pdf?sig=xxxxxxxxxxxxxxxxxxxx",
        "https://docs.example.com/v2?Signature=signature-goes-here",
        "See https://discord.com/api/v10/webhooks for the docs.",
        "mysql -u root -p appdb",
        "mysql -u root -p < dump.sql",
        "htpasswd -n alice",
        "htpasswd -nB alice >> users.htpasswd",
        "Authorization: Digest is described in RFC 7616.",
        "http://localhost:5173/@vite/client",
        "https://example.com:8443/@alice/notes",
        "https://medium.com/@alice/a-post-title",
        "DATABASE_URL=postgres://db.example.com/app",
    ];
    lines.iter().map(|line| (*line).to_string()).collect()
}
