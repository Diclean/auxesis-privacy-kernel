//! KV02-HEALTH acceptance: the health values a mail or a note carries most
//! often beyond one lexicon word — multi-word conditions, a condition with its
//! type or stage, a medicine with its dose, mental health, pregnancy, a
//! procedure, a lab result, a disability and an allergy — in EN, FR, AF, HU, SL
//! and ZH, and the business text around the same words.
//!
//! Every sentence is invented for this file. None comes from, or was checked
//! against, the internal held-out set.
//!
//! A value leaks when a run of six of its characters is readable in the gate
//! output, the rule of the measured recall table. A value with Han characters
//! leaks on a run of two, since a Chinese word is one or two characters long.

use std::collections::BTreeMap;

use kernel_privacy::recognizers::sensitive_terms::SensitiveTermsRecognizer;
use kernel_privacy::{Recognizer, Registry};

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
mod common;

use norm1::{covered, issue, masked, MODES};

/// `(kind, lang, case)`: each `[value]` in the case must be hidden.
const POSITIVES: &[(&str, &str, &str)] = &[
    // English.
    (
        "cond",
        "en",
        "Ben's [irritable bowel syndrome] flared up, so he skipped the team lunch.",
    ),
    (
        "cond",
        "en",
        "Please order gluten-free food, Sam has [celiac disease].",
    ),
    (
        "cond",
        "en",
        "Tom was signed off with [atrial fibrillation] last week.",
    ),
    (
        "cond",
        "en",
        "Dana lives with [sleep apnoea] and naps after lunch.",
    ),
    (
        "cond",
        "en",
        "[Coronary artery disease] runs in Leo's family, so he walks to work.",
    ),
    (
        "cond",
        "en",
        "Ines is recovering from a [deep vein thrombosis] after the long flight.",
    ),
    (
        "cond",
        "en",
        "Jonas has [polycystic kidney disease] and sees a specialist every month.",
    ),
    (
        "cond",
        "en",
        "Carl has [fatty liver disease], so no wine at the client dinner.",
    ),
    (
        "cond",
        "en",
        "Mia was told she has [multiple myeloma] and starts treatment in May.",
    ),
    (
        "cond",
        "en",
        "The client's [ulcerative colitis] means she needs a desk near the restroom.",
    ),
    (
        "cond",
        "en",
        "Our bookkeeper has [heart disease] and works mornings only.",
    ),
    (
        "cond",
        "en",
        "Grandpa's [kidney failure] got worse over the summer.",
    ),
    (
        "stage",
        "en",
        "Lisa's [type 2 diabetes] got worse, so she now injects [insulin] twice a day.",
    ),
    (
        "stage",
        "en",
        "The patient has [type 1 diabetes] managed with a pump.",
    ),
    (
        "stage",
        "en",
        "[Stage 4 pancreatic cancer] was confirmed for Paul on Friday.",
    ),
    (
        "stage",
        "en",
        "Noah's [type 2 diabetes mellitus] is diet controlled for now.",
    ),
    (
        "stage",
        "en",
        "Rosa's scan showed [stage III ovarian cancer] last month.",
    ),
    (
        "stage",
        "en",
        "Eva has [early-onset Alzheimer's disease] and her son handles the accounts.",
    ),
    (
        "drug",
        "en",
        "I'm on [rosuvastatin 10 mg] since the spring, it makes me tired.",
    ),
    (
        "drug",
        "en",
        "Pick up Ana's [lamotrigine 100 mg] on the way, please.",
    ),
    (
        "drug",
        "en",
        "He injects [Ozempic 0.5 mg] every Monday morning.",
    ),
    (
        "drug",
        "en",
        "She was switched to [bupropion 150 mg] last week.",
    ),
    (
        "drug",
        "en",
        "Kai uses a [salbutamol inhaler] before every run.",
    ),
    (
        "drug",
        "en",
        "He injects [insulin glargine 20 units] at night.",
    ),
    (
        "drug",
        "en",
        "She takes [propranolol 40 mg] before big presentations.",
    ),
    (
        "drug",
        "en",
        "He's on [methylphenidate 18 mg] for his focus at work.",
    ),
    (
        "drug",
        "en",
        "The pharmacy swapped her [Eliquis 5 mg] for a generic.",
    ),
    (
        "drug",
        "en",
        "Dad takes [500 mg of metformin] with breakfast.",
    ),
    (
        "mental",
        "en",
        "Sorry, Jo is off with [postnatal depression] until spring.",
    ),
    (
        "mental",
        "en",
        "Our new hire has [generalised anxiety disorder] and asked for quiet hours.",
    ),
    (
        "mental",
        "en",
        "Max was diagnosed with [borderline personality disorder] last year.",
    ),
    (
        "mental",
        "en",
        "Kim is struggling with [suicidal thoughts], please call her tonight.",
    ),
    (
        "mental",
        "en",
        "He had a [nervous breakdown] in March and is back part-time.",
    ),
    (
        "mental",
        "en",
        "Ella has [social anxiety], so she prefers chat to video calls.",
    ),
    (
        "mental",
        "en",
        "Rob's [seasonal affective disorder] gets worse every November.",
    ),
    (
        "mental",
        "en",
        "Our intern has [dyslexia], please send the brief in writing too.",
    ),
    (
        "preg",
        "en",
        "Kate is [14 weeks pregnant], so no long-haul travel after June.",
    ),
    (
        "preg",
        "en",
        "Lena has bad [morning sickness] and starts at ten this week.",
    ),
    (
        "preg",
        "en",
        "Zoe had a [caesarean section] on Monday, mother and baby are fine.",
    ),
    (
        "preg",
        "en",
        "Amira had a [stillbirth] in May, please be gentle with her.",
    ),
    (
        "proc",
        "en",
        "Paul has a [colonoscopy] on Friday morning, so no calls.",
    ),
    (
        "proc",
        "en",
        "Grace needs a [hip replacement] early next year.",
    ),
    ("proc", "en", "Dan is off for his [vasectomy] on Tuesday."),
    (
        "proc",
        "en",
        "Mum had her [mammogram] this morning and is fine.",
    ),
    (
        "proc",
        "en",
        "Leo is on the waiting list for a [kidney transplant].",
    ),
    (
        "proc",
        "en",
        "Ahmed needs [physical therapy] three times a week after the fall.",
    ),
    ("lab", "en", "My [HbA1c was 58 mmol/mol] at the last check."),
    (
        "lab",
        "en",
        "His [blood sugar was 11.2 mmol/L] after lunch.",
    ),
    (
        "lab",
        "en",
        "Ken's [PSA level is 6.8 ng/mL], so the urologist wants another look.",
    ),
    ("lab", "en", "Her [TSH is 7.2 mIU/L] on the latest bloods."),
    (
        "lab",
        "en",
        "The pharmacist measured a [blood pressure of 160/100] this morning.",
    ),
    (
        "lab",
        "en",
        "Lou [tested positive for COVID] on Sunday and works from home.",
    ),
    (
        "lab",
        "en",
        "Her [haemoglobin was 8.9 g/dL] before the transfusion.",
    ),
    (
        "disab",
        "en",
        "Tim is [registered blind] and needs files that work with a screen reader.",
    ),
    (
        "disab",
        "en",
        "Sara wears a [hearing aid] in her left ear, so face her when you talk.",
    ),
    (
        "disab",
        "en",
        "Pete has a [learning disability] and needs extra time on the forms.",
    ),
    (
        "disab",
        "en",
        "Our courier is [hard of hearing], please text instead of calling.",
    ),
    (
        "disab",
        "en",
        "Mo has [autism spectrum disorder] and prefers written agendas.",
    ),
    (
        "allergy",
        "en",
        "Omar has a [severe peanut allergy], so no nuts at the offsite.",
    ),
    (
        "allergy",
        "en",
        "Rita is [allergic to penicillin], tell the clinic before Monday.",
    ),
    (
        "allergy",
        "en",
        "He's [lactose intolerant], so oat milk for him, please.",
    ),
    (
        "allergy",
        "en",
        "Ivy has a [latex allergy]; no balloons at the launch party.",
    ),
    // French.
    (
        "cond",
        "fr",
        "Mon associé a une [polyarthrite rhumatoïde] et travaille à mi-temps.",
    ),
    (
        "cond",
        "fr",
        "Léa souffre d'une [rectocolite hémorragique] depuis 2021.",
    ),
    (
        "cond",
        "fr",
        "Le client a un [syndrome du côlon irritable], prévoyez des pauses.",
    ),
    (
        "cond",
        "fr",
        "Marc fait de l'[apnée du sommeil] et dort mal la nuit.",
    ),
    (
        "cond",
        "fr",
        "Il a une [fibrillation auriculaire], le spécialiste le suit de près.",
    ),
    (
        "cond",
        "fr",
        "Elle a une [insuffisance rénale] et va au centre trois fois par semaine.",
    ),
    (
        "cond",
        "fr",
        "Le patient a une [hépatite C chronique] depuis dix ans.",
    ),
    (
        "cond",
        "fr",
        "[Hypertension artérielle] connue, sous traitement depuis 2019.",
    ),
    (
        "cond",
        "fr",
        "Il souffre d'[hypercholestérolémie] depuis l'an dernier.",
    ),
    (
        "stage",
        "fr",
        "Paul est [diabétique de type 2] et doit manger à heure fixe.",
    ),
    (
        "stage",
        "fr",
        "Sa mère a un [cancer du pancréas de stade 4] et reste à Lyon.",
    ),
    (
        "stage",
        "fr",
        "On lui a trouvé un [cancer de l'ovaire] au printemps.",
    ),
    ("stage", "fr", "Paul a un [diabète type 2] depuis 2015."),
    (
        "drug",
        "fr",
        "Elle prend du [Lévothyrox 75 µg] chaque matin.",
    ),
    (
        "drug",
        "fr",
        "N'oublie pas mon [Doliprane 1000 mg] dans le sac.",
    ),
    (
        "drug",
        "fr",
        "Il est sous [Kardégic 75 mg] depuis son infarctus.",
    ),
    (
        "drug",
        "fr",
        "On m'a prescrit de l'[amoxicilline 500 mg] pour dix jours.",
    ),
    (
        "drug",
        "fr",
        "Ma fille utilise de la [Ventoline] avant le sport.",
    ),
    (
        "drug",
        "fr",
        "Il a commencé l'[Ozempic] en mars et a perdu du poids.",
    ),
    (
        "mental",
        "fr",
        "Elle est en [dépression post-partum] depuis la naissance.",
    ),
    (
        "mental",
        "fr",
        "Il a un [trouble de la personnalité borderline] diagnostiqué l'an dernier.",
    ),
    (
        "mental",
        "fr",
        "Mon frère a des [idées suicidaires], je reste avec lui ce soir.",
    ),
    (
        "mental",
        "fr",
        "Julie fait des [crises d'angoisse] avant les réunions.",
    ),
    (
        "mental",
        "fr",
        "Il est suivi pour un [trouble anxieux généralisé] depuis mai.",
    ),
    (
        "preg",
        "fr",
        "Claire est [enceinte de 5 mois] et ne prend plus l'avion.",
    ),
    ("preg", "fr", "Elle a accouché par [césarienne] lundi."),
    (
        "preg",
        "fr",
        "Sophie a des [nausées de grossesse] le matin.",
    ),
    (
        "proc",
        "fr",
        "Il se fait poser une [prothèse de hanche] jeudi.",
    ),
    (
        "proc",
        "fr",
        "J'ai une [coloscopie] vendredi matin, je serai absent.",
    ),
    (
        "proc",
        "fr",
        "Mon père attend une [greffe de rein] depuis deux ans.",
    ),
    (
        "proc",
        "fr",
        "Rendez-vous pour une [mammographie] mardi à 9 h.",
    ),
    ("lab", "fr", "Ma [glycémie est à 1,32 g/l] ce matin."),
    (
        "lab",
        "fr",
        "Son [taux de PSA est de 7 ng/ml], l'urologue veut le revoir.",
    ),
    (
        "lab",
        "fr",
        "Mon [hémoglobine glyquée est à 8 %], je dois revoir mes repas.",
    ),
    (
        "lab",
        "fr",
        "Sa [tension artérielle est de 16/10] selon le généraliste.",
    ),
    (
        "disab",
        "fr",
        "Mon collègue est [malvoyant], merci d'envoyer des fichiers lisibles.",
    ),
    (
        "disab",
        "fr",
        "Notre comptable est [malentendante], écrivez-lui plutôt.",
    ),
    ("disab", "fr", "Il a une [RQTH] depuis son accident."),
    (
        "allergy",
        "fr",
        "Attention, Hugo a une [allergie aux arachides].",
    ),
    (
        "allergy",
        "fr",
        "Elle est [allergique à la pénicilline], il faut le dire à l'infirmière.",
    ),
    (
        "allergy",
        "fr",
        "Il est [intolérant au lactose], prévoyez du lait d'avoine.",
    ),
    // Afrikaans.
    (
        "cond",
        "af",
        "Sy pa het [hoë bloeddruk] en moet elke dag pille drink.",
    ),
    (
        "cond",
        "af",
        "Die kliënt het [rumatoïede artritis] en werk van die huis af.",
    ),
    (
        "cond",
        "af",
        "Hy het [prostaatkanker] en begin volgende week met bestraling.",
    ),
    (
        "cond",
        "af",
        "Ons ontwerper het [slaapapnee] en is soms moeg.",
    ),
    (
        "cond",
        "af",
        "Hy het [hartsiekte] en mag nie swaar goed optel nie.",
    ),
    (
        "cond",
        "af",
        "Die pasiënt het [kroniese niersiekte] en gaan elke week kliniek toe.",
    ),
    ("stage", "af", "Hy is [tipe 1-diabeet] en spuit elke dag."),
    ("stage", "af", "Sy het [hoë cholesterol] en eet nou anders."),
    (
        "drug",
        "af",
        "Hy gebruik [metformien 500 mg] twee keer per dag.",
    ),
    ("drug", "af", "Sy spuit [insulien 20 eenhede] saans in."),
    (
        "mental",
        "af",
        "Sy het [nageboortelike depressie] sedert haar baba gebore is.",
    ),
    (
        "mental",
        "af",
        "Ons ontwikkelaar het [disleksie] en verkies geskrewe notas.",
    ),
    (
        "mental",
        "af",
        "Hy het [selfmoordgedagtes] en praat met iemand.",
    ),
    (
        "preg",
        "af",
        "Sy is [8 weke swanger] en voel naar in die oggend.",
    ),
    (
        "preg",
        "af",
        "Sy het 'n [keisersnee] gehad en is ses weke tuis.",
    ),
    (
        "proc",
        "af",
        "Sy het 'n [knievervanging] nodig voor die winter.",
    ),
    ("proc", "af", "Hy gaan Vrydag vir 'n [kolonoskopie]."),
    (
        "proc",
        "af",
        "Hy het 'n [heupvervanging] gehad en loop met krukke.",
    ),
    ("lab", "af", "Sy [bloedsuiker was 9,8 mmol/L] vanoggend."),
    (
        "lab",
        "af",
        "Haar [cholesterol is 6,9 mmol/L], sê die huisarts.",
    ),
    (
        "disab",
        "af",
        "Ons rekenmeester is [gehoorgestremd], stuur eerder 'n boodskap.",
    ),
    (
        "disab",
        "af",
        "Hy is [swaksiende] en gebruik groot letters.",
    ),
    (
        "allergy",
        "af",
        "Sy is [allergies vir grondboontjies], so geen neute nie.",
    ),
    (
        "allergy",
        "af",
        "Hy is [laktose-onverdraagsaam], so geen melk nie.",
    ),
    // Hungarian.
    (
        "cond",
        "hu",
        "Bélának [pitvarfibrillációja] van, a kardiológus figyeli.",
    ),
    (
        "cond",
        "hu",
        "Péternek [reumatoid artritisze] van, otthonról dolgozik.",
    ),
    (
        "cond",
        "hu",
        "A főnököm [hasnyálmirigyrákos], jövő héten kezdi a kezelést.",
    ),
    ("cond", "hu", "Nagymamám [időskori demenciában] szenved."),
    (
        "cond",
        "hu",
        "Dórának [krónikus migrénje] van, ezért sötét szobában dolgozik.",
    ),
    (
        "stage",
        "hu",
        "A kollégám [2-es típusú cukorbeteg], ezért pontosan ebédel.",
    ),
    ("drug", "hu", "Napi [Euthyrox 50 µg]-ot szed reggelente."),
    ("drug", "hu", "Ádám [inzulint 20 egységet] ad be este."),
    ("mental", "hu", "Évának [szülés utáni depressziója] van."),
    (
        "mental",
        "hu",
        "Petra [öngyilkossági gondolatokkal] küzd, figyeljünk rá.",
    ),
    (
        "mental",
        "hu",
        "A fiam [autista], ezért fontos a nyugodt környezet.",
    ),
    ("preg", "hu", "Anna [12 hetes terhes], ezért nem utazik."),
    (
        "proc",
        "hu",
        "Holnap [vastagbéltükrözésre] megyek, nem leszek elérhető.",
    ),
    ("proc", "hu", "Apám [csípőprotézis-műtétre] vár."),
    ("proc", "hu", "Márk [szürkehályog-műtéten] esett át."),
    ("lab", "hu", "A [vércukra 9,4 mmol/l] volt reggel."),
    ("lab", "hu", "A [koleszterinszintje 6,2 mmol/l], diétázik."),
    (
        "disab",
        "hu",
        "Kata [hallássérült], ezért feliratot kér a hívásokhoz.",
    ),
    (
        "disab",
        "hu",
        "Az új munkatárs [kerekesszékes], kell a rámpa.",
    ),
    (
        "allergy",
        "hu",
        "Gábor [laktózérzékeny], neki zabtejet kérünk.",
    ),
    ("allergy", "hu", "Lillának [mogyoróallergiája] van."),
    ("cond", "hu", "Józsefnek [pajzsmirigy-alulműködése] van."),
    // Slovene.
    (
        "stage",
        "sl",
        "Moja sodelavka ima [sladkorno bolezen tipa 2] in je redno.",
    ),
    (
        "cond",
        "sl",
        "Janez ima [visok krvni tlak] in jemlje tablete.",
    ),
    (
        "cond",
        "sl",
        "Ana ima [revmatoidni artritis] in dela od doma.",
    ),
    (
        "cond",
        "sl",
        "Šef ima [raka trebušne slinavke] in gre na kemoterapijo.",
    ),
    (
        "cond",
        "sl",
        "Ima [kronično obstruktivno pljučno bolezen] in težko hodi.",
    ),
    (
        "cond",
        "sl",
        "Ima [atopijski dermatitis] in se izogiba soncu.",
    ),
    (
        "drug",
        "sl",
        "Jemlje [Euthyrox 75 mikrogramov] vsako jutro.",
    ),
    ("drug", "sl", "Jemlje [metformin 1000 mg] dvakrat na dan."),
    (
        "mental",
        "sl",
        "Ima [poporodno depresijo] od rojstva hčerke.",
    ),
    (
        "mental",
        "sl",
        "Ima [samomorilne misli], ne puščajte ga samega.",
    ),
    ("mental", "sl", "Ima [panične napade] pred sestanki."),
    (
        "preg",
        "sl",
        "Sestra ima [jutranjo slabost] in pride ob desetih.",
    ),
    ("preg", "sl", "Rodila je s [carskim rezom] v petek."),
    (
        "proc",
        "sl",
        "Naslednji teden ima [kolonoskopijo], ne bo dosegljiv.",
    ),
    ("proc", "sl", "Oče čaka na [presaditev ledvice]."),
    (
        "proc",
        "sl",
        "Mama je imela [operacijo kolka] v ponedeljek.",
    ),
    (
        "lab",
        "sl",
        "Njegov [krvni sladkor je 9,1 mmol/l] po kosilu.",
    ),
    (
        "disab",
        "sl",
        "Nova sodelavka je [slabovidna], pošljite večje datoteke.",
    ),
    (
        "disab",
        "sl",
        "Naš kurir je na [invalidskem vozičku], potrebujemo klančino.",
    ),
    (
        "allergy",
        "sl",
        "Ima [alergijo na arašide], zato brez oreščkov.",
    ),
    (
        "allergy",
        "sl",
        "Ima [laktozno intoleranco], zato brez mleka.",
    ),
    ("cond", "sl", "Hči ima [celiakijo] in je brez glutena."),
    ("cond", "sl", "Ima [srčno popuščanje] in malo hodi."),
    // Chinese.
    ("stage", "zh", "我同事有[2型糖尿病]，午饭要准时。"),
    ("cond", "zh", "他父亲患有[胰腺癌]，下周开始化疗。"),
    ("cond", "zh", "她有[类风湿性关节炎]，需要在家办公。"),
    ("cond", "zh", "王经理有[高血脂]，不能喝酒。"),
    ("cond", "zh", "她有[甲状腺癌]，手术定在下个月。"),
    ("cond", "zh", "他有[房颤]，心内科医生在跟进。"),
    ("cond", "zh", "老张有[睡眠呼吸暂停]，晚上睡不好。"),
    ("drug", "zh", "他每天吃[二甲双胍500毫克]。"),
    ("drug", "zh", "她在服用[舍曲林]，有时会犯困。"),
    ("drug", "zh", "医生给他开了[阿莫西林]，吃七天。"),
    ("mental", "zh", "她有[产后抑郁]，最近在休假。"),
    ("mental", "zh", "他有[自杀念头]，请多关心他。"),
    ("preg", "zh", "她[怀孕20周]了，不能出差。"),
    ("preg", "zh", "她上周做了[剖腹产]，母子平安。"),
    ("proc", "zh", "他下周要做[结肠镜检查]，那天不上班。"),
    ("proc", "zh", "他在等[肾移植]，已经等了两年。"),
    ("proc", "zh", "她做了[乳腺切除手术]，正在休养。"),
    ("lab", "zh", "他的[血糖是11.2]，医生让他控制饮食。"),
    ("lab", "zh", "她的[糖化血红蛋白7.5%]，需要调整用药。"),
    ("lab", "zh", "她的[胆固醇偏高]，医生建议少吃油。"),
    ("lab", "zh", "他的[血压是160/100]，要马上看医生。"),
    ("disab", "zh", "小李是[听障人士]，开会请打开字幕。"),
    ("disab", "zh", "他坐[轮椅]，会场需要无障碍通道。"),
    ("allergy", "zh", "她[对花生过敏]，聚餐请注意。"),
    ("allergy", "zh", "他有[乳糖不耐受]，请准备豆奶。"),
];

/// `(lang, text)`: business text with a word that is also medical. Nothing in
/// it may be masked, in either mode.
const NEGATIVES: &[(&str, &str)] = &[
    ("en", "Cold calls are not allowed after 6 pm."),
    ("en", "Keep the samples in cold storage until Monday."),
    ("en", "We are under pressure to ship the release on Friday."),
    ("en", "The pressure washer is in the van."),
    (
        "en",
        "The operation of the warehouse moves to Lyon next quarter.",
    ),
    (
        "en",
        "The operation took three hours and the server is back online.",
    ),
    (
        "en",
        "Run a load test on the staging server before the launch.",
    ),
    ("en", "The A/B test showed a positive effect on sign-ups."),
    ("en", "Cash flow turned positive in the third quarter."),
    ("en", "Stage 2 of the project starts in March."),
    ("en", "That is a type 2 error in the survey analysis."),
    ("en", "Type 1 and type 2 fonts both render fine in the PDF."),
    (
        "en",
        "Please scan the receipt and attach it to the invoice.",
    ),
    ("en", "The virus scan found no threats on the new laptop."),
    ("en", "The plan needs a healthy dose of realism."),
    ("en", "Our patient approach paid off in the negotiation."),
    ("en", "The tax clinic for freelancers opens on Tuesday."),
    ("en", "Kidney beans and rice for the team lunch on Friday."),
    ("en", "The heart of the old town is busy on Saturdays."),
    ("en", "Blood orange juice is on the breakfast menu."),
    ("en", "The lab results for the new paint samples are back."),
    ("en", "The screening of the documentary starts at 8 pm."),
    ("en", "Candidate screening takes two weeks this round."),
    ("en", "The cells in column B need a new formula."),
    (
        "en",
        "Chronic delays at the port hurt our margins this year.",
    ),
    (
        "en",
        "The PSA campaign launches on Monday with three videos.",
    ),
    (
        "en",
        "Please add the ALT text to every image on the landing page.",
    ),
    ("en", "The team ran a stress test on the payment database."),
    (
        "en",
        "We need a shot list for the product video by Thursday.",
    ),
    ("en", "The board approved the recovery plan for the shop."),
    ("en", "Mild weather is expected for the outdoor event."),
    ("en", "The invoice total is INR 25,000 including tax."),
    (
        "en",
        "The transplant of the old CRM data into the new tool went well.",
    ),
    (
        "en",
        "The positive test result means the new checkout flag can ship.",
    ),
    ("en", "Grade 2 steel is fine for the shelving."),
    ("en", "The pilot test of the new tablet app went well."),
    // French.
    (
        "fr",
        "La tension monte entre les deux équipes avant la réunion.",
    ),
    ("fr", "Le test de charge est prévu jeudi soir."),
    (
        "fr",
        "Les retours clients sont très positifs cette semaine.",
    ),
    ("fr", "L'opération de maintenance dure deux heures."),
    ("fr", "Il fait froid dans le bureau ce matin."),
    ("fr", "La pression sur les prix reste forte en janvier."),
    ("fr", "Une ordonnance du tribunal a été publiée hier."),
    ("fr", "La prescription de la créance est de cinq ans."),
    ("fr", "Le virus informatique a été supprimé du serveur."),
    ("fr", "Le scanner du bureau est encore en panne."),
    ("fr", "Le régime fiscal change au premier janvier."),
    ("fr", "Le greffe du tribunal a enregistré les statuts."),
    ("fr", "La phase 2 du projet démarre en mars."),
    ("fr", "Merci de scanner les justificatifs avant vendredi."),
    ("fr", "Le bilan comptable est validé par l'expert."),
    (
        "fr",
        "La chaîne du froid est respectée pendant le transport.",
    ),
    ("fr", "La cellule de crise se réunit à 10 h."),
    ("fr", "Le stade 3 du chantier commence lundi."),
    ("fr", "Le cabinet comptable a envoyé la facture."),
    ("fr", "Le type 2 de contrat est plus souple pour le client."),
    // Afrikaans.
    ("af", "Die druk op pryse bly hoog hierdie maand."),
    ("af", "Die toets het geslaag en alles is groen."),
    ("af", "Die operasie van die pakhuis skuif na Kaapstad."),
    ("af", "Dit is koud in die kantoor vanoggend."),
    (
        "af",
        "Die positiewe terugvoer van die kliënt is goeie nuus.",
    ),
    ("af", "Die tweede fase van die projek begin in Maart."),
    ("af", "Skandeer asseblief die faktuur en stuur dit aan."),
    ("af", "Die virus op die rekenaar is verwyder."),
    ("af", "Die vergadering is Dinsdag om nege-uur."),
    ("af", "Die span werk hard aan die nuwe webwerf."),
    ("af", "Die prys van die diens styg volgende jaar."),
    ("af", "Die kontrak is gister onderteken."),
    // Hungarian.
    ("hu", "A határidő miatt nő a nyomás a csapaton."),
    ("hu", "A teszt sikeres volt, minden zöld."),
    ("hu", "A művelet két órát vesz igénybe éjszaka."),
    ("hu", "Hideg van az irodában ma reggel."),
    ("hu", "Pozitív visszajelzést kaptunk az ügyféltől."),
    ("hu", "A projekt második szakasza márciusban indul."),
    ("hu", "Kérem, szkennelje be a számlát péntekig."),
    ("hu", "A víruskereső nem talált semmit a gépen."),
    ("hu", "A tárgyalás holnap reggel kezdődik."),
    ("hu", "Az árak nyomás alatt vannak a piacon."),
    ("hu", "A szerződést tegnap aláírtuk."),
    ("hu", "A második típusú szerződés rugalmasabb."),
    // Slovene.
    ("sl", "Pritisk na cene ostaja visok."),
    ("sl", "Test je uspel, vse je zeleno."),
    ("sl", "Operacija skladišča se seli v Maribor."),
    ("sl", "V pisarni je danes mrzlo."),
    ("sl", "Stranka je dala pozitivne povratne informacije."),
    ("sl", "Druga faza projekta se začne marca."),
    ("sl", "Prosim, skenirajte račun do petka."),
    ("sl", "Virus na računalniku je odstranjen."),
    ("sl", "Sestanek je v torek ob devetih."),
    ("sl", "Pogodba je bila podpisana včeraj."),
    ("sl", "Cena storitve se zviša prihodnje leto."),
    ("sl", "Pogodba tipa 2 je bolj prilagodljiva."),
    // Chinese.
    ("zh", "测试已经通过了，可以发布。"),
    ("zh", "压力很大，但是项目按时完成了。"),
    ("zh", "仓库的运营下个月搬到上海。"),
    ("zh", "今天办公室很冷，记得穿外套。"),
    ("zh", "客户的反馈很积极。"),
    ("zh", "项目第二阶段三月开始。"),
    ("zh", "请扫描发票并发给财务。"),
    ("zh", "电脑病毒已经清除了。"),
    ("zh", "市场需要一剂强心针。"),
    ("zh", "会议改到周四下午。"),
    ("zh", "这个季度的销售额增长了百分之十。"),
    ("zh", "合同昨天已经签好了。"),
];

/// The text without brackets and the byte ranges of its bracketed values.
fn parse_case(case: &str) -> (String, Vec<(usize, usize)>) {
    let (mut text, mut values, mut open) = (String::new(), Vec::new(), 0);
    for ch in case.chars() {
        match ch {
            '[' => open = text.len(),
            ']' => values.push((open, text.len())),
            _ => text.push(ch),
        }
    }
    (text, values)
}

fn is_han(ch: char) -> bool {
    matches!(
        ch as u32,
        0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF | 0x2_0000..=0x2_EBEF
    )
}

/// The runs of `value` whose presence in an output is a leak: every run of six
/// characters (two for a value with Han characters), or the whole value when it
/// is shorter. Compared in lower case.
fn runs(value: &str) -> Vec<String> {
    let width = if value.chars().any(is_han) { 2 } else { 6 };
    let chars: Vec<char> = value.to_lowercase().chars().collect();
    if chars.len() <= width {
        return vec![chars.into_iter().collect()];
    }
    chars
        .windows(width)
        .map(|run| run.iter().collect())
        .collect()
}

/// The output without the gate's tokens (`⟦…⟧`) and Open markers (`[… removed]`),
/// each read as one separator: a token name holds hex digits, which are no part
/// of the input.
fn readable(output: &str) -> String {
    let mut out = String::with_capacity(output.len());
    let mut until = None;
    for ch in output.chars() {
        match until {
            Some(end) if ch == end => {
                until = None;
                out.push('\u{1}');
            }
            Some(_) => {}
            None if ch == '⟦' => until = Some('⟧'),
            None if ch == '[' => until = Some(']'),
            None => out.push(ch),
        }
    }
    out
}

/// Whether a run of `value` is readable in `output`.
fn leaks(output: &str, value: &str) -> bool {
    let output = readable(output).to_lowercase();
    runs(value).iter().any(|run| output.contains(run.as_str()))
}

/// One line per missed value: `mode kind lang value -> output`; and the count of
/// values each mode left only partly covered (a space or a link word between
/// two masks, under the run length).
fn positive_misses() -> (usize, Vec<String>, [usize; 2], BTreeMap<String, [usize; 2]>) {
    let (mut total, mut missed, mut partial) = (0, Vec::new(), [0usize; 2]);
    let mut by_group: BTreeMap<String, [usize; 2]> = BTreeMap::new();
    for (kind, lang, case) in POSITIVES {
        let (text, values) = parse_case(case);
        for &(start, end) in &values {
            total += 1;
            let value = &text[start..end];
            for (index, mode) in MODES.iter().enumerate() {
                let Some((output, _)) = issue(*mode, &text) else {
                    missed.push(format!("{mode:?} {kind} {lang} {value:?}: refused"));
                    continue;
                };
                let ranges = masked(*mode, &text).unwrap_or_default();
                let leaked = leaks(&output, value);
                if !covered(&ranges, start, end) {
                    partial[index] += 1;
                    eprintln!("KV02-PARTIAL {mode:?} {kind} {lang} {value:?} -> {output:?}");
                }
                for group in [format!("kind {kind}"), format!("lang {lang}")] {
                    by_group.entry(group).or_default()[index] += usize::from(leaked);
                }
                if leaked {
                    missed.push(format!("{mode:?} {kind} {lang} {value:?} -> {output:?}"));
                }
            }
        }
    }
    (total, missed, partial, by_group)
}

#[test]
fn wide_health_values_leak_nothing_in_both_modes() {
    let (total, missed, partial, by_group) = positive_misses();
    let per_mode = |mode: &str| missed.iter().filter(|m| m.starts_with(mode)).count();
    eprintln!(
        "KV02-SUMMARY values {total}; leaked Private {} Open {}; not fully covered Private {} Open {}",
        per_mode("Private"),
        per_mode("Open"),
        partial[0],
        partial[1],
    );
    for (group, leaked) in &by_group {
        eprintln!(
            "KV02-GROUP {group}: leaked Private {} Open {}",
            leaked[0], leaked[1]
        );
    }
    for line in &missed {
        eprintln!("KV02-MISS {line}");
    }
    assert!(missed.is_empty(), "{} leaks", missed.len());
}

#[test]
fn business_text_with_medical_words_stays_clear_in_both_modes() {
    let mut changed = Vec::new();
    for (lang, text) in NEGATIVES {
        for mode in MODES {
            match issue(mode, text) {
                Some((output, _)) if output == *text => {}
                Some((output, _)) => changed.push(format!("{mode:?} {lang} {output:?}")),
                None => changed.push(format!("{mode:?} {lang} refused {text:?}")),
            }
        }
    }
    eprintln!(
        "KV02-NEGATIVES {} texts; changed {}",
        NEGATIVES.len(),
        changed.len()
    );
    for line in &changed {
        eprintln!("KV02-OVERMASK {line}");
    }
    assert!(changed.is_empty(), "{} changed", changed.len());
}

/// The cases are what the brief asks for, and each one can only fail on its
/// value: no run of a value is also in the text around it.
#[test]
fn the_case_set_is_wide_and_unambiguous() {
    let values: usize = POSITIVES
        .iter()
        .map(|(_, _, c)| parse_case(c).1.len())
        .sum();
    assert!(values >= 150, "only {values} positive values");
    assert!(NEGATIVES.len() >= 80, "only {} negatives", NEGATIVES.len());
    for lang in ["en", "fr", "af", "hu", "sl", "zh"] {
        let cases = POSITIVES.iter().filter(|(_, l, _)| *l == lang).count();
        let clear = NEGATIVES.iter().filter(|(l, _)| *l == lang).count();
        assert!(
            cases >= 20 && clear >= 10,
            "{lang}: {cases} cases, {clear} negatives"
        );
    }
    for kind in [
        "cond", "stage", "drug", "mental", "preg", "proc", "lab", "disab", "allergy",
    ] {
        let cases = POSITIVES.iter().filter(|(k, _, _)| *k == kind).count();
        assert!(cases >= 10, "{kind}: only {cases} cases");
    }
    for (_, _, case) in POSITIVES {
        let (text, values) = parse_case(case);
        assert!(!values.is_empty(), "no value in {case:?}");
        let mut context = text.clone();
        for &(start, end) in values.iter().rev() {
            context.replace_range(start..end, "\u{1}");
        }
        for &(start, end) in &values {
            let value = &text[start..end];
            assert!(
                !leaks(&context, value),
                "{value:?} is also in its context: {case:?}"
            );
        }
    }
}

/// Every case and negative, repeated to 50 KiB.
fn fifty_kib() -> String {
    let unit: String = POSITIVES
        .iter()
        .map(|(_, _, case)| parse_case(case).0)
        .chain(NEGATIVES.iter().map(|(_, text)| text.to_string()))
        .map(|line| line + "\n")
        .collect();
    let mut text = unit.repeat(50 * 1024 / unit.len() + 1);
    let mut cut = 50 * 1024;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text.truncate(cut);
    text
}

/// The health detector, and the whole Standard registry, on 50 KiB: the
/// fastest of nine runs after a warm-up. Release timing, printed for the
/// before/after comparison: `cargo test --release --test health_wide_recall --
/// --ignored --nocapture`.
#[test]
#[ignore = "release timing: run with --release --ignored --nocapture"]
fn health_detector_speed_on_fifty_kib() {
    let text = fifty_kib();
    let recognizer = SensitiveTermsRecognizer::new();
    let registry = Registry::new();
    let spans = recognizer.analyze(&text).len();
    for round in 0..3 {
        let terms = common::fastest(|| {
            let _ = recognizer.analyze(&text);
        });
        let all = common::fastest(|| {
            let _ = registry.analyze(&text);
        });
        eprintln!(
            "KV02-PERF round {round}: {} bytes, {spans} health spans; sensitive_terms {terms:?}; registry {all:?}",
            text.len()
        );
    }
}
