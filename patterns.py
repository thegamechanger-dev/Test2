# patterns.py
import re

# --- Configuration Variables (defaults, can be overridden by config.ini) ---
# MIN_USERNAME_LENGTH is primarily controlled by config.ini in main.py after loading.
# Keeping it here provides a default if config fails or for reference.
MIN_USERNAME_LENGTH = 5

# --- Regex Patterns ---
# These patterns are used by check_for_links_enhanced in main.py.
# Ensure these are updated based on your specific requirements for forbidden content.

# General website URLs
PATTERNS_SPECIFIC_URLS = [
    r"https?://(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:[/?#][^\s<>\"']*)?",
    r"http?://(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:[/?#][^\s<>\"']*)?",
    r"ftp://(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:[/?#][^\s<>\"']*)?",
    r"\bwww\d{0,3}\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:[/?#][^\s<>\"']*)?\b",
]

# Telegram-specific links
PATTERNS_TELEGRAM_LINKS = [
    # General t.me/username or t.me/channel links (public)
    r"\b(?:t\.me|telegram\.me|telegram\.dog)/[a-zA-Z0-9_]{" + str(MIN_USERNAME_LENGTH) + r",32}(?:[/?][^\s<>\"']*)?\b",
    # Joinchat links (private channels/groups) - covers +, joinchat/, etc.
    r"\b(?:t\.me|telegram\.me|telegram\.dog)/(?:joinchat/[a-zA-Z0-9_/\-]+|\+[a-zA-Z0-9_/\-]+)\b",
    # Links with query parameters like start, startgroup, etc.
    r"\b(?:t\.me|telegram\.me|telegram\.dog)/[a-zA-Z0-9_]{" + str(MIN_USERNAME_LENGTH) + r",32}\?(?:start|startgroup|admin)=[^\s<>\"']*\b",
    # tg://resolve links (app links)
    r"\btg://resolve\?domain=[a-zA-Z0-9_]{" + str(MIN_USERNAME_LENGTH) + r",32}(?:&(?:start|startgroup|admin)=[^\s<>\"']*)?\b",
    # Contact links
    r"\b(?:t\.me|telegram\.me|telegram\.dog)/contact\?text=[^\s<>\"']*\b",
    r"\b(?:t\.me|telegram\.me|telegram\.dog)/contact/[a-zA-Z0-9_/\-]+\b",
    # Message links t.me/c/chat_id/message_id
    r"\b(?:t\.me|telegram\.me|telegram\.dog)/c/\d+/\d+\b",
]

# Regex for detecting evasions (like using 'dot' or spaces instead of '.')
COMMON_EVASION_TLDS = r"(?:com|net|org|info|biz|ru|de|uk|co|io|gg|me|xyz|club|site|online|shop|store|app|dev|live|stream|icu|top|buzz|guru)"
PATTERNS_EVASION_DOT = [
    # Matches "site dot com", "site d0t com", "site . com"
    r"\b[a-zA-Z0-9\-]+(?:\s*\[?\(?\s*(?:dot|d0t|\.)\s*\)?\]?|\s+(?:dot|d0t)\s+)[a-zA-Z0-9\-]+\." + COMMON_EVASION_TLDS + r"\b",
]

# New patterns for plain domains and obfuscated Telegram links
COMMON_TLDS = r"(?:com|net|org|info|biz|ru|de|uk|co|io|me|xyz|app|dev|club|site|online|shop|store|live)"
PATTERN_DOMAIN = r"\b[a-zA-Z0-9-]{1,63}\." + COMMON_TLDS + r"(?:/[^\s<>\"']*)?\b"
PATTERN_TELEGRAM_OBFUSCATED = r"\b(?:t\.me|telegram\.me|telegram\.dog)\s*[/:]\s*[a-zA-Z0-9_]{5,32}(?:[/?][^\s<>\"']*)?\b"

# Combine all forbidden patterns
FORBIDDEN_PATTERNS_LIST = (
    PATTERNS_SPECIFIC_URLS +
    PATTERNS_TELEGRAM_LINKS +
    PATTERNS_EVASION_DOT +
    [PATTERN_DOMAIN, PATTERN_TELEGRAM_OBFUSCATED]
)
COMBINED_FORBIDDEN_PATTERN = "|".join(FORBIDDEN_PATTERNS_LIST) if FORBIDDEN_PATTERNS_LIST else r"a^"

# --- Forbidden Keywords/Words ---
FORBIDDEN_WORDS = [
    # Variations of 'bio'
    r"\bb[i1!𝒊𝕚]o\b",
    r"\bb\W*i\W*o\b",
    r"\bbio(?:\s+or\s+link)\b",
    r"\bbio(?:[^\w]|$)",
    # Variations of 'profile'
    r"\bpr[o0]+f[i1!𝒊𝕚]+l[e3]+\b",
    r"\bpr\W*o+\W*f\W*i\W*l\W*e+\b",
    # Variations of 'link'
    r"\blinks?\b",
    r"\bl\W*i\W*n\W*k\b",
    r"\bl\W*y\W*n\W*k\b",
    r"🔗",
    # Variations of 'sell', 'sale', 'salesman', 'seller'
    r"\bs[e3]l{2,}\b",
    r"\bs\W*e\W*l\W*l+\b",
    r"\bs[4a@][l1!𝒍𝕝][e3]\b",
    r"\bs[4a@][l1!𝒍𝕝][e3]s[m𝖒][4a@][n𝖓]\b",
    r"\bs[4a@][l1!𝒍𝕝][l1!𝒍𝕝][e3]r\b",
    r"\bcoll\W*ection\b",
    # Generic calls to action
    r"\bin\W*bio\b",
    r"\bin\W*profile\b",
    # Sensitive content
    r"\bcp\b",
    r"\bc[/\\]?p\b",
    r"\bc\W?p\b",
    r"\bch[i1!]ld\b",
    r"\bc\W*h\W*i\W*l\W*d\b",
    r"\bcollection\b",
    r"\bcol\W*lection\b",
    # Unicode and Hindi variants
    r"\bbyo\b",
    r"\bb\W*a\W*y\W*o\b",
    r"\bchannel\b",
    r"\bchanel\b",
    r"\bchan\W*l\b",
    r"\bc\W*h\W*a\W*n\W*e\W*l\b",
    r"बायो",
    r"ब\W*ा\W*इ\W*य\W*ो",
    r"ग्रुप",
    r"ग\W*र\W*ू\W*प",
    r"लिंक",
    r"ल\W*ि\W*क",
    r"प्रोफाइल",
    r"प\W*र\W*ो\W*फ\W*ा\W*ई\W*ल",
    r"चैनल",
    r"च\W*ै\W*न\W*ल",
    r"ग\W*ु\W*र\W*ू\W*प",
    r"ब\W*ा\W*य\W*ो\W*द\W*े\W*ख\W*ك\W*र\W*क\W*ْ\W*य\W*ा\W*ك\W*र\W*ो\W*گ\W*े",
    r"से\W*ल\b",
    r"से\W*ल\W*्\W*स\W*म\W*ै\W*न\b",
    r"व\W*ि\W*क\W*्\W*र\W*े\W*त\W*ा\b",
    r"क\W*ले\W*क\W*्\W*श\W*न\b",
    # Persian patterns
    r"\bبدون\W*سانسور\b",
    r"\bفیلم\W*بدون\W*سانسور\b",
    r"\bسریال\W*بدون\W*سانسور\b",
]

# --- Whitelist Patterns ---
WHITELIST_PATTERNS = [
    r"^no\s+bio\b.*",
    r"\bbio(?:tech|logy|graphy|metric|nic)\b",
    r"\bprofile\s*(pic|picture|photo|link|url)\b",
    r"\bpm\s+me\b",
    r"\bdm\s+me\b",
    r"\bn[o0]\W*b[i1!𝒊𝕚]o\b",
    r"\bb[i1!𝒊𝕚]o\W*dekh\W*kar\W*kya\W*karoge\b",
    r"बायो\W*देख\W*कर\W*क्या\W*करोगे\b",
]

# --- User-Facing Text Strings ---
# These are messages, prompts, and button texts displayed to users/admins.
# Maintain consistency in placeholders (e.g., {user_mention}, {chat_id}, {duration_formatted}).
# Use HTML ParseMode where appropriate (e.g., for bold, code blocks, mentions).

# Required patterns checked in main.py (ensure these are defined)
# Reason templates added to the list of reasons for action
SENDER_PROFILE_VIOLATION_REASON = "Sender's profile ({field}) contains issues: {issue_type}"
MESSAGE_VIOLATION_REASON = "Message contains forbidden content: {message_issue_type}"
MENTIONED_USER_PROFILE_VIOLATION_REASON = "Mentioned user(s) profile violation: {users_summary}"
NEW_USER_PROFILE_VIOLATION_REASON = "New user's profile ({field}) contains issues: {issue_type}"
SENDER_IS_BAD_ACTOR_REASON = {
    "english": "Thou art marked a knave for vile deeds past, and thus art shunned!",
    "hindi": "तू पूर्व के घृणित कर्मों हेतु दुष्ट ठहराया गया, अतः तुझे बहिष्कृत किया जाता है!"
}

# Dialogues for bio link/profile issue detection (Original Shakespearean + Hindi)
# Used in take_action for the sender's punishment message
BIO_LINK_DIALOGUES_LIST = [
    {"english": ("O reckless knave, thy bio doth betray!\nWith vile links that spread corruption’s seed.\nPurge this filth, or face our righteous wrath,\nFor purity we guard with iron will."), "hindi": ("हे लापरवाह दुष्ट, तेरा बायो धोखा देता!\nघृणित लिंक्स जो भ्रष्टाचार के बीज बोते।\nइस मैल को साफ कर, वरना हमारे धर्मी क्रोध का सामना कर,\nक्योंकि हम पवित्रता की रक्षा लौह इच्छा से करते हैं।")},
    {"english": ("Fie upon thee, whose bio bears foul links,\nA herald of deceit and base intent.\nRemove these chains, or be cast out anon,\nOur group shall stand untainted and pure."), "hindi": ("धिक्कार है तुझ पर, जिसका बायो घृणित लिंक्स रखता,\nधोखे और नीच इरादों का संदेशवाहक।\nइन जंजीरों को हटाओ, नहीं तो जल्द बाहर फेंका जाओगे,\nहमारा समूह शुद्ध और निर्मल रहेगा।")},
    {"english": ("O foul betrayer, thy bio doth proclaim\nA siren’s call to chaos and deceit.\nCut these ties, or suffer swift expulsion,\nFor here no villain’s shadow shall abide."), "hindi": ("हे घृणित धोखेबाज, तेरा बायो घोषणा करता है है\nअराजकता और छल का सायरन कॉल।\nइन बंधनों को काट, नहीं तो त्वरित निष्कासन सह,\nहमारा समूह शुद्ध और निर्मल रहेगा।")},
    {"english": ("Thy bio, a plague upon our sacred trust,\nSpreading venom with each cursed link.\nCleanse thyself, or be forever shunned,\nFor purity’s sake, we cast thee out."), "hindi": ("तेरा बायो, हमारे पवित्र विश्वास पर प्लेग है,\nहर शापित लिंक से विष फैलाता।\nअपने आप को साफ कर, नहीं तो सदा के लिए बहिष्कृत हो,\nपवित्रता के लिए, हम तुझे बाहर फेंक देते हैं।")},
    {"english": ("O knave, whose bio doth corrupt the pure,\nWith links that sow the seeds of ruin.\nPurge this filth, or face eternal scorn,\nOur sentinel shall guard this hallowed ground."), "hindi": ("हे दुष्ट, जिसका बायो शुद्ध को भ्रष्ट करता,\nऐसे लिंक्स जो विनाश के बीज बोते।\nइस मैल को साफ कर, नहीं तो सदा के लिए तिरस्कार सह,\nहमारा प्रहरी इस पवित्र भूमि की रक्षा करेगा।")},
    {"english": ("Thou art a traitor, thy bio stained with lies,\nA serpent’s tongue that poisons all who read.\nBe cleansed, or be forever cast aside,\nFor here we tolerate no venomous creed."), "hindi": ("तू एक द्रोही है, तेरा बायो झूठ से दागदार,\nएक सांप की जीभ जो पढ़ने वालों को ज़हरीला बनाती।\nसाफ हो जा, नहीं तो सदा के लिए बाहर फेंक दिया जाएगा,\nक्योंकि यहाँ हम विषैले विश्वास को सहन नहीं करते।")},
    {"english": ("Your personal scroll, the bio, now bears a mark of transgression, a tangled web of forbidden threads that threaten to ensnare the unwary.\nUntangle this digital deceit, or face the grim unraveling of your presence within these hallowed halls, forever banished from our sight."), "hindi": ("तुम्हारा व्यक्तिगत स्क्रॉल, बायो, अब उल्लंघन का एक निशान धारण करता है, वर्जित धागों का एक उलझा हुआ जाल जो असावधान को फंसाने की धमकी देता है।\nइस डिजिटल धोखे को सुलझाओ, या इन पवित्र हॉल के भीतर तुम्हारी उपस्थिति के भयावह बिखराव का सामना करो, हमारी दृष्टि से हमेशा के लिए निर्वासित।")},
    {"english": ("Lo, a treacherous link has woven its way into the very fabric of thy bio, a venomous serpent lurking within our pristine digital garden.\nRemove this vile blight without delay, lest the righteous indignation of the guardians descend upon thee, casting thee forth into the desolate wastes of banishment."), "hindi": ("देखो, एक कपटी लिंक तुम्हारे बायो के ताने-बाने में बुना गया है, हमारे प्राचीन डिजिटल उद्यान के भीतर छिपा हुआ एक जहरीला सर्प।\nइस घृणित विपत्ति को बिना किसी देरी के हटाओ, कहीं संरक्षकों का धर्मी क्रोध तुम पर न उतर जाए, तुम्हें निर्वासन के उजाड़ रेगिस्तान में फेंकते हुए।")},
    {"english": ("By the solemn decree of the elders and the sacred tenets of this community, no alien links shall defile the sanctity of thy personal scroll.\nAmend this grievous error with utmost haste and restore its purity, or be forever unlisted from our sacred registry, your name erased from our collective memory."), "hindi": ("बुजुर्गों के गंभीर फरमान और इस समुदाय के पवित्र सिद्धांतों द्वारा, कोई बाहरी लिंक तुम्हारे व्यक्तिगत स्क्रॉल की पवित्रता को दूषित नहीं करेगा।\nइस गंभीर त्रुटि को अत्यंत शीघ्रता से सुधारो और इसकी पवित्रता को बहाल करो, या हमारे पवित्र रजिस्टर से हमेशा के लिए अचिह्नित हो जाओ, तुम्हारा नाम हमारी सामूहिक स्मृति से मिटा दिया जाएगा।")},
    {"english": ("This digital taint, this insidious mark of forbidden knowledge embedded within your bio, shall not be permitted to stand.\nCleanse this defilement with righteous fervor, removing every trace of its corruption, or be irrevocably scrubbed from the annals of our records, your existence here forgotten."), "hindi": ("तुम्हारे बायो के भीतर निहित यह डिजिटल दाग, वर्जित ज्ञान का यह कपटी निशान, खड़ा होने की अनुमति नहीं दी जाएगी।\nइस अपवित्रता को धर्मी उत्साह के साथ साफ करो, इसके भ्रष्टाचार के हर निशान को हटाते हुए, या हमारे अभिलेखों के इतिहास से अपरिवर्तनीय रूप से मिटा दिए जाओ, यहाँ तुम्हारा अस्तित्व भुला दिया जाएगा।")},
    {"english": ("Beware, O user, the hidden path your bio so brazenly proclaims, for it is a treacherous route leading directly to the precipice of expulsion.\nRectify this perilous course without hesitation, for if you fail, the swift hand of justice shall cast you into the abyss, never to return."), "hindi": ("सावधान, हे उपयोगकर्ता, तुम्हारे बायो द्वारा इतनी बेशर्मी से घोषित छिपे हुए मार्ग से, क्योंकि यह एक कपटी मार्ग है जो सीधे निष्कासन के कगार पर ले जाता है।\nइस खतरनाक मार्ग को बिना किसी झिझक के सुधारो, क्योंकि यदि तुम असफल रहे, तो न्याय का त्वरित हाथ तुम्हें खाई में फेंक देगा, कभी वापस नहीं लौटने के लिए।")},
    {"english": ("The very utterance of your bio, through its illicit link, echoes into realms unknown and forbidden, drawing unwanted attention and ill intent.\nSilence this perilous connection immediately, for if you persist, you shall be silenced yourself, your voice extinguished from our discourse forever."), "hindi": ("तुम्हारे बायो का उच्चारण ही, अपने अवैध लिंक के माध्यम से, अज्ञात और वर्जित लोकों में गूँजता है, अवांछित ध्यान और बुरे इरादों को आकर्षित करता है।\nइस खतरनाक संबंध को तुरंत चुप कराओ, क्योंकि यदि तुम जारी रहे, तो तुम स्वयं चुप करा दिए जाओगे, तुम्हारी आवाज हमारे प्रवचन से हमेशा के लिए बुझ जाएगी।")},
    {"english": ("Behold, a digital tether, deceptively spun, now pulls your very essence towards the desolate shores of exile, a consequence of your bio's forbidden link.\nSever this binding chain with unwavering resolve, or be cast adrift upon the boundless currents of isolation, never to find safe harbor again."), "hindi": ("देखो, एक डिजिटल बंधन, धोखे से बुना गया, अब तुम्हारे सार को निर्वासन के उजाड़ किनारों की ओर खींचता है, तुम्हारे बायो के वर्जित लिंक का परिणाम।\nइस बंधनकारी श्रृंखला को अटूट संकल्प के साथ तोड़ो, या अलगाव की असीमित धाराओं पर भटक जाओ, कभी फिर से सुरक्षित बंदरगाह नहीं मिलेगा।")},
    {"english": ("The sacred sanctity of our collective space has been grievously defiled by the external gate your bio has so carelessly thrown open.\nClose this illicit portal without delay, for if you refuse, you shall find yourself locked out from our fellowship, forever barred from its comforting embrace."), "hindi": ("हमारे सामूहिक स्थान की पवित्रता को तुम्हारे बायो द्वारा इतनी लापरवाही से खोले गए बाहरी द्वार से गंभीर रूप से दूषित किया गया है।\nइस अवैध पोर्टल को बिना किसी देरी के बंद करो, क्योंकि यदि तुम इनकार करते हो, तो तुम स्वयं को हमारी संगति से बाहर पाओगे, इसके आरामदायक आलिंगन से हमेशा के लिए वर्जित।")},
    {"english": ("Your bio, a furtive whisper in the digital winds, speaks of a forbidden connection, a secret pact with forces unseen.\nMake this declaration pure and untainted, reflecting only the virtuous, or face immediate disconnection from the very essence of our unity, becoming a solitary phantom."), "hindi": ("तुम्हारा बायो, डिजिटल हवाओं में एक गुप्त फुसफुसाहट, एक वर्जित संबंध की बात करता है, अनदेखी शक्तियों के साथ एक गुप्त समझौता।\nइस घोषणा को शुद्ध और अदूषित बनाओ, केवल गुणी को दर्शाते हुए, या हमारी एकता के सार से तत्काल डिस्कनेक्शन का सामना करो, एक एकाकी प्रेत बन जाओ।")},
    {"english": ("Like a venomous vine, insidious and suffocating, your bio's link has begun to choke the delicate harmony that binds our community.\nUproot this noxious growth with resolute action, for if it remains, you shall be severed from our thriving collective, cast aside like withered foliage."), "hindi": ("एक जहरीली बेल की तरह, कपटी और दम घोंटने वाली, तुम्हारे बायो के लिंक ने हमारे समुदाय को बांधने वाली नाजुक सद्भाव को गला घोंटना शुरू कर दिया है।\nइस हानिकारक वृद्धि को दृढ़ कार्रवाई के साथ जड़ से उखाड़ो, क्योंकि यदि यह बनी रहती है, तो तुम हमारे फलते-फूलते समूह से काट दिए जाओगे, सूखे पत्तों की तरह अलग कर दिए जाओगे।")},
    {"english": ("A forbidden portal, dark and foreboding, has brazenly torn open within the very discourse of this channel, threatening to unleash chaos.\nSeal this rupture with unwavering resolve, for if it remains unchecked, the channel itself shall be silenced, its vibrant voice extinguished forevermore."), "hindi": ("एक वर्जित पोर्टल, काला और अशुभ, इस चैनल के प्रवचन के भीतर बेशर्मी से खुल गया है, अराजकता फैलाने की धमकी दे रहा है।\nइस दरार को अटूट संकल्प के साथ बंद करो, क्योंकि यदि यह अनियंत्रित रहता है, तो चैनल ही चुप करा दिया जाएगा, इसकी जीवंत आवाज हमेशा के लिए बुझ जाएगी।")},
    {"english": ("This channel, a sacred sanctuary for shared thoughts and pure communion, is now grievously marred by an external beacon, an unwelcome intrusion.\nRemove the intrusive link without delay, or face the inevitable dimming of its light, its vibrant existence fading into obscurity."), "hindi": ("यह चैनल, साझा विचारों और शुद्ध संगति के लिए एक पवित्र अभयारण्य, अब एक बाहरी बीकन, एक अवांछित घुसपैठ से गंभीर रूप से दागदार है।\nबिना किसी देरी के आक्रामक लिंक को हटाओ, या इसकी रोशनी के अनिवार्य मंद होने का सामना करो, इसका जीवंत अस्तित्व अस्पष्टता में लुप्त हो जाएगा।")},
    {"english": ("Hark! A serpent's whisper, insidious and subtle, has woven itself as a forbidden link within the very flow of this channel's vital currents.\nCast this venomous blight out without hesitation, ere the pure waters of our discourse turn foul and corrupt, poisoning all who partake."), "hindi": ("सुनो! एक सर्प की फुसफुसाहट, कपटी और सूक्ष्म, इस चैनल के महत्वपूर्ण धाराओं के प्रवाह के भीतर एक वर्जित लिंक के रूप में बुना गया है।\nइस जहरीली विपत्ति को बिना किसी झिझक के बाहर निकालो, इससे पहले कि हमारे प्रवचन के शुद्ध पानी गंदे और भ्रष्ट हो जाएं, सभी को जहरीला कर दें।")},
    {"english": ("The intricate threads of this channel's being were never intended for the weaving of external webs, foreign and disruptive to our harmony.\nUntangle the illicit link from its delicate tapestry, or the very loom upon which our discussions are spun shall cease its rhythmic beat, bringing all to a standstill."), "hindi": ("इस चैनल के अस्तित्व के जटिल धागे कभी भी बाहरी जालों को बुनने के लिए नहीं थे, जो हमारी सद्भाव के लिए विदेशी और विघटनकारी हों।\nइसके नाजुक टेपेस्ट्री से अवैध लिंक को सुलझाओ, या वह करघा जिस पर हमारी चर्चाएँ बुनी जाती हैं, अपनी लयबद्ध धड़कन बंद कर देगा, सब कुछ ठप कर देगा।")},
    {"english": ("This channel's sacred space, a bastion of shared purpose, is emphatically not for foreign inroads or external entanglements.\nRecant the forbidden link with unwavering resolve, for if you persist in its defiance, you shall suffer the swift and decisive closure of this very conduit, severing all connection."), "hindi": ("इस चैनल का पवित्र स्थान, साझा उद्देश्य का एक गढ़, बाहरी घुसपैठ या बाहरी उलझनों के लिए बिल्कुल नहीं है।\nवर्जित लिंक को अटूट संकल्प के साथ त्याग दो, क्योंकि यदि तुम इसके अवज्ञा में बने रहते हो, तो तुम इस बहुत ही माध्यम के त्वरित और निर्णायक बंद होने का सामना करोगे, सभी कनेक्शनों को काटते हुए।")},
    {"english": ("A digital tendril, insidious and grasping, your link seeks to ensnare the very essence of this channel, pulling it into shadow.\nClip this parasitic growth with decisive action, or bear witness to the channel withered and barren, its once vibrant life force drained away."), "hindi": ("एक डिजिटल बेल, कपटी और लोभी, तुम्हारा लिंक इस चैनल के सार को फंसाने की कोशिश करता है, इसे छाया में खींचता है।\nइस परजीवी वृद्धि को निर्णायक कार्रवाई के साथ काटो, या चैनल को मुरझाया हुआ और बंजर देखो, इसकी एक बार की जीवंत जीवन शक्ति सूख गई।")},
    {"english": ("The very voice of this channel, a symphony of shared wisdom and collective understanding, must remain pure and unadulterated.\nMuffle the intrusive external link that seeks to corrupt its melody, for if it persists, its song shall be forever silenced, its harmonies lost to the winds."), "hindi": ("इस चैनल की आवाज, साझा ज्ञान और सामूहिक समझ की एक सिम्फनी, शुद्ध और अदूषित रहनी चाहिए।\nउस आक्रामक बाहरी लिंक को दबाओ जो इसकी धुन को भ्रष्ट करना चाहता है, क्योंकि यदि यह बनी रहती है, तो इसका गीत हमेशा के लिए चुप करा दिया जाएगा, इसकी सद्भाव हवाओं में खो जाएगी।")},
    {"english": ("Be warned, a treacherous path, subtly laid by your link within this channel, leads directly to the abyss of ruin and desolation.\nBlock this perilous route with unwavering determination, for if you hesitate, the path shall be irrevocably severed, leading to an irreversible downfall."), "hindi": ("सावधान रहो, एक कपटी मार्ग, इस चैनल के भीतर तुम्हारे लिंक द्वारा सूक्ष्मता से बिछाया गया, सीधे विनाश और उजाड़ के खाई में ले जाता है।\nइस खतरनाक मार्ग को अटूट दृढ़ संकल्प के साथ अवरुद्ध करो, क्योंकि यदि तुम झिझकते हो, तो मार्ग अपरिवर्तनीय रूप से काट दिया जाएगा, जिससे एक अपरिवर्तनीय पतन होगा।")},
    {"english": ("The very essence, the vital spirit of this channel, vehemently rejects the external bond you seek to forge, an unwelcome intrusion.\nBreak this illicit connection with resolute action, for if it remains, you shall face the complete dissolution of its form, its purpose lost forever."), "hindi": ("इस चैनल का सार, इसका महत्वपूर्ण आत्मा, तुम्हारे द्वारा बनाने की कोशिश किए जा रहे बाहरी बंधन को जोरदार तरीके से अस्वीकार करता है, एक अवांछित घुसपैठ।\nइस अवैध संबंध को दृढ़ कार्रवाई के साथ तोड़ो, क्योंकि यदि यह बनी रहती है, तो तुम इसके रूप के पूर्ण विघटन का सामना करोगे, इसका उद्देश्य हमेशा के लिए खो जाएगा।")},
    {"english": ("The inherent sanctity of this channel demands unceasing vigilance against all forms of external corruption and invasive influence.\nRemove the intrusive link immediately, for if it lingers, its very gates shall be irrevocably barred, locking out all access and communion."), "hindi": ("इस चैनल की अंतर्निहित पवित्रता सभी प्रकार के बाहरी भ्रष्टाचार और आक्रामक प्रभाव के खिलाफ निरंतर सतर्कता की मांग करती है।\nआक्रामक लिंक को तुरंत हटाओ, क्योंकि यदि यह रहता है, तो इसके द्वार अपरिवर्तनीय रूप से बंद कर दिए जाएंगे, सभी पहुंच और संगति को रोकते हुए।")},
    {"english": ("Thy words, once pristine and pure, now carry a defiling mark, a forbidden utterance that pollutes the very air of our discourse.\nRecant this vile declaration without delay, for if you hesitate, your voice shall be muted forevermore, never again to resonate within these sacred confines."), "hindi": ("तुम्हारे शब्द, एक बार प्राचीन और शुद्ध, अब एक अपवित्र निशान धारण करते हैं, एक वर्जित उच्चारण जो हमारे प्रवचन की हवा को ही प्रदूषित करता है।\nइस घृणित घोषणा को बिना किसी देरी के त्याग दो, क्योंकि यदि तुम झिझकते हो, तो तुम्हारी आवाज हमेशा के लिए मौन कर दी जाएगी, इन पवित्र सीमाओं के भीतर फिर कभी प्रतिध्वनित नहीं होगी।")},
    {"english": ("A whisper of deceit, subtle yet corrosive, now manifests as a hidden link within the very heart of your message, threatening to unravel trust.\nErase this insidious mark with unwavering resolve, or your voice shall be forever stifled, its very essence silenced from our collective ear."), "hindi": ("धोखे की फुसफुसाहट, सूक्ष्म लेकिन संक्षारक, अब तुम्हारे संदेश के बहुत दिल के भीतर एक छिपे हुए लिंक के रूप में प्रकट होती है, विश्वास को तोड़ने की धमकी देती है।\nइस कपटी निशान को अटूट संकल्प के साथ मिटाओ, या तुम्हारी आवाज हमेशा के लिए दबा दी जाएगी, इसका सार हमारी सामूहिक कान से चुप करा दिया जाएगा।")},
    {"english": ("This digital parchment, intended for pure and honest communication, now holds a forbidden script, a clandestine message.\nAmend your message immediately, purging it of this illicit inscription, or it shall be ceremoniously burned from our records, leaving no trace behind."), "hindi": ("यह डिजिटल चर्मपत्र, शुद्ध और ईमानदार संचार के लिए अभिप्रेत, अब एक वर्जित लिपि, एक गुप्त संदेश धारण करता है।\nअपने संदेश को तुरंत सुधारो, इस अवैध शिलालेख से इसे शुद्ध करते हुए, या इसे हमारे अभिलेखों से औपचारिक रूप से जला दिया जाएगा, कोई निशान नहीं छोड़ते हुए।")},
    {"english": ("Like a virulent plague, unseen yet potent, your message carries a forbidden word, threatening to infect the very core of our shared dialogue.\nPurge this contaminant with extreme prejudice, or you shall be quarantined from the healthy body of our speech, isolated in silence."), "hindi": ("एक घातक प्लेग की तरह, अनदेखा फिर भी शक्तिशाली, तुम्हारा संदेश एक वर्जित शब्द धारण करता है, हमारे साझा संवाद के बहुत मूल को संक्रमित करने की धमकी देता है।\nइस दूषित पदार्थ को अत्यधिक पूर्वाग्रह के साथ शुद्ध करो, या तुम्हें हमारी वाणी के स्वस्थ शरीर से संगरोधित किया जाएगा, चुप्पी में अलग कर दिया जाएगा।")},
    {"english": ("Hark, a dark omen now manifests, a perilous link insidiously embedded within your very transmission, portending ill fate.\nSever this ominous connection without delay, for if it persists, your messages shall irrevocably cease, your communications halted by an unseen force."), "hindi": ("सुनो, एक काला शगुन अब प्रकट होता है, तुम्हारे प्रसारण के भीतर कपटपूर्ण रूप से एम्बेडेड एक खतरनाक लिंक, बुरे भाग्य का संकेत देता है।\nइस अशुभ संबंध को बिना किसी देरी के तोड़ो, क्योंकि यदि यह बनी रहती है, तो तुम्हारे संदेश अपरिवर्तनीय रूप से बंद हो जाएंगे, तुम्हारे संचार एक अनदेखी शक्ति द्वारा रोक दिए जाएंगे।")},
    {"english": ("Your message, though seemingly innocuous, acts as a carrier of an unwelcome guest, a forbidden word that corrupts its intent.\nExpel this illicit intruder with swift action, for if it remains, you shall face the swift and decisive expulsion yourself, banished from our midst."), "hindi": ("तुम्हारा संदेश, हालांकि दिखने में हानिरहित, एक अवांछित मेहमान का वाहक के रूप में कार्य करता है, एक वर्जित शब्द जो इसके इरादे को भ्रष्ट करता है।\nइस अवैध घुसपैठिए को त्वरित कार्रवाई के साथ बाहर निकालो, क्योंकि यदि यह रहता है, तो तुम स्वयं त्वरित और निर्णायक निष्कासन का सामना करोगे, हमारे बीच से निर्वासित।")},
    {"english": ("The very air of our cherished chat, once pure and invigorating, is now grievously tainted by the insidious link embedded within your message.\nCleanse this defilement with utmost urgency, or you shall find yourself unable to breathe the clean air of our discourse, forever excluded from its purity."), "hindi": ("हमारी प्यारी चैट की हवा ही, एक बार शुद्ध और स्फूर्तिदायक, अब तुम्हारे संदेश के भीतर निहित कपटी लिंक से गंभीर रूप से दूषित होती है।\nइस अपवित्रता को अत्यंत शीघ्रता से साफ करो, या तुम स्वयं को हमारे प्रवचन की स्वच्छ हवा में सांस लेने में असमर्थ पाओगे, इसकी पवित्रता से हमेशा के लिए बाहर।")},
    {"english": ("A serpent's hiss, a vile and insidious sound, is the forbidden word escaping your very lips, polluting the sanctity of our conversation.\nGuard your tongue with zealous vigilance, for if it falters, you shall be irrevocably muzzled, your voice silenced by the weight of your transgression."), "hindi": ("एक सर्प की फुफकार, एक घृणित और कपटी ध्वनि, तुम्हारे होठों से निकलता वर्जित शब्द है, हमारी बातचीत की पवित्रता को प्रदूषित करता है।\nअपनी जिह्वा को अत्यधिक सतर्कता के साथ संभालो, क्योंकि यदि यह लड़खड़ाती है, तो तुम्हें अपरिवर्तनीय रूप से बांध दिया जाएगा, तुम्हारी आवाज तुम्हारे उल्लंघन के भार से चुप करा दी जाएगी।")},
    {"english": ("Your message, a digital missive, now bears a grim mark of the forbidden, a stain upon its very integrity that cannot be ignored.\nRemove this defiling brand without delay, or you shall be forever marked as an outcast, irrevocably severed from our collective and its trust."), "hindi": ("तुम्हारा संदेश, एक डिजिटल पत्र, अब वर्जित का एक गंभीर निशान धारण करता है, इसकी अखंडता पर एक दाग जिसे अनदेखा नहीं किया जा सकता है।\nइस अपवित्र ब्रांड को बिना किसी देरी के हटाओ, या तुम हमेशा के लिए एक बहिष्कृत के रूप में चिह्नित हो जाओगे, हमारे समूह और उसके विश्वास से अपरिवर्तनीय रूप से काट दिए जाओगे।")},
    {"english": ("The inherent purity of our communal communication has been grievously breached by the illicit link you have so carelessly inserted.\nSeal this festering wound with immediate action, for if it remains, you shall be irrevocably severed from our network, cast out into digital isolation."), "hindi": ("तुम्हारे द्वारा इतनी लापरवाही से डाले गए अवैध लिंक से हमारी सांप्रदायिक संचार की अंतर्निहित पवित्रता गंभीर रूप से भंग हुई है।\nइस फैलते घाव को तत्काल कार्रवाई के साथ बंद करो, क्योंकि यदि यह रहता है, तो तुम हमारे नेटवर्क से अपरिवर्तनीय रूप से काट दिए जाओगे, डिजिटल अलगाव में बाहर फेंक दिए जाओगे।")},
    {"english": ("A discordant note, jarring and offensive, your forbidden word now mars the delicate harmony that defines our discourse.\nSilence this cacophony with unwavering resolve, or your voice shall become forever unheard, lost in the clamor of your own transgressions."), "hindi": ("एक बेसुरा स्वर, कष्टप्रद और आपत्तिजनक, तुम्हारा वर्जित शब्द अब उस नाजुक सद्भाव को बिगाड़ता है जो हमारे प्रवचन को परिभाषित करता है।\nइस कोलाहल को अटूट संकल्प के साथ चुप कराओ, या तुम्हारी आवाज हमेशा के लिए अनसुनी हो जाएगी, तुम्हारे अपने उल्लंघनों के कोलाहल में खो जाएगी।")},
    {"english": ("Your message, a deceptive key, now unlocks portals to forbidden realms, inviting shadows and chaos into our tranquil space.\nRelinquish this illicit link without delay, for if you persist, you shall be forever locked out from our sanctuary, barred from its safety and peace."), "hindi": ("तुम्हारा संदेश, एक भ्रामक कुंजी, अब वर्जित लोकों के पोर्टलों को खोलता है, हमारे शांत स्थान में छाया और अराजकता को आमंत्रित करता है।\nइस अवैध लिंक को बिना किसी देरी के छोड़ दो, क्योंकि यदि तुम जारी रहे, तो तुम्हें हमारे अभयारण्य से हमेशा के लिए बाहर कर दिया जाएगा, इसकी सुरक्षा और शांति से वर्जित।")},
    {"english": ("By the ancient and unwavering laws that govern our interactions, no such profane word shall ever pass through these hallowed channels.\nRetract this egregious utterance immediately, for if you fail, your inherent right to speak freely shall be irrevocably forfeit, silenced by your own folly."), "hindi": ("प्राचीन और अटूट कानूनों द्वारा जो हमारी बातचीत को नियंत्रित करते हैं, ऐसा कोई अपवित्र शब्द कभी भी इन पवित्र चैनलों से पारित नहीं होगा।\nइस घृणित उच्चारण को तुरंत वापस ले लो, क्योंकि यदि तुम असफल रहे, तो बोलने का तुम्हारा अंतर्निहित अधिकार अपरिवर्तनीय रूप से जब्त हो जाएगा, तुम्हारी अपनी मूर्खता से चुप कर दिया जाएगा।")},
    {"english": ("A chilling shadow creeps insidiously into the very essence of your message, cast by a link to forbidden places, dark and perilous.\nBanish this malevolent presence without hesitation, for if it remains, you shall find yourself compelled to dwell in unending darkness, severed from the light."), "hindi": ("एक भयावह छाया तुम्हारे संदेश के सार में कपटपूर्ण रूप से रेंगती है, वर्जित स्थानों के एक लिंक द्वारा डाली गई, अंधेरा और खतरनाक।\nइस दुर्भावनापूर्ण उपस्थिति को बिना किसी झिझक के भगाओ, क्योंकि यदि यह बनी रहती है, तो तुम स्वयं को अंतहीन अंधेरे में रहने के लिए मजबूर पाओगे, प्रकाश से काट दिए जाओगे।")},
    {"english": ("The very fabric of our shared discourse, delicately woven and cherished, is now grievously torn by your profane and offensive word.\nMend this gaping wound with immediate action, for if it festers, you shall be unstitched from the very tapestry of our community, cast out as a loose thread."), "hindi": ("हमारे साझा प्रवचन का ताना-बाना ही, नाजुक ढंग से बुना और पोषित, अब तुम्हारे अपवित्र और आपत्तिजनक शब्द से गंभीर रूप से फटा हुआ है।\nइस बड़े घाव को तत्काल कार्रवाई के साथ ठीक करो, क्योंकि यदि यह फैलता है, तो तुम्हें हमारे समुदाय के ताने-बाने से अलग कर दिया जाएगा, एक ढीले धागे के रूप में बाहर फेंक दिया जाएगा।")},
    {"english": ("Your message, a digital thorn, now pierces the very side of our collective harmony, all due to the insidious forbidden link it contains.\nExtract this painful intrusion with resolute precision, for if it remains embedded, you shall be cast out from our healing circle, left to fester alone."), "hindi": ("तुम्हारा संदेश, एक डिजिटल कांटा, अब हमारी सामूहिक सद्भाव के बहुत पक्ष को छेदता है, यह सब इसमें निहित कपटी वर्जित लिंक के कारण है।\nइस दर्दनाक घुसपैठ को दृढ़ सटीकता के साथ निकालो, क्योंकि यदि यह बना रहता है, तो तुम्हें हमारे उपचार चक्र से बाहर फेंक दिया जाएगा, अकेले सड़ने के लिए छोड़ दिया जाएगा।")},
    {"english": ("The very echoes of your message, reverberating through our space, now contain a forbidden and dissonant sound, a corrupting resonance.\nErase this illicit vibration without delay, for if it persists, your voice will irrevocably vanish, its pure resonance forever lost to the winds."), "hindi": ("तुम्हारे संदेश की गूँज ही, हमारे स्थान के माध्यम से प्रतिध्वनित होती है, अब एक वर्जित और बेसुरा ध्वनि धारण करती है, एक भ्रष्ट अनुनाद।\nइस अवैध कंपन को बिना किसी देरी के मिटाओ, क्योंकि यदि यह बनी रहती है, तो तुम्हारी आवाज अपरिवर्तनीय रूप से गायब हो जाएगी, इसकी शुद्ध अनुनाद हवाओं में हमेशा के लिए खो जाएगी।")},
    {"english": ("A rogue current, turbulent and disruptive, your link within this message now profoundly disturbs the harmonious flow of our communication.\nRedirect this aberrant energy with swift and decisive action, or you shall be irrevocably cut off from our vital stream, drifting aimlessly."), "hindi": ("एक बदमाश धारा, अशांत और विघटनकारी, इस संदेश में तुम्हारा लिंक अब हमारे संचार के सामंजस्यपूर्ण प्रवाह को गहराई से बाधित करता है।\nइस aberrant ऊर्जा को त्वरित और निर्णायक कार्रवाई के साथ पुनर्निर्देशित करो, या तुम्हें हमारी महत्वपूर्ण धारा से अपरिवर्तनीय रूप से काट दिया जाएगा, लक्ष्यहीन रूप से भटकते हुए।")},
    {"english": ("Your words, meant to convey meaning, now bear a grim mark of corruption, a forbidden link that sullies their very essence.\nPurify them with zealous intent, stripping away all defilement, or you shall be forever seen as unclean, your utterances tainted beyond redemption."), "hindi": ("तुम्हारे शब्द, अर्थ व्यक्त करने के लिए अभिप्रेत, अब भ्रष्टाचार का एक गंभीर निशान धारण करते हैं, एक वर्जित लिंक जो उनके सार को ही दूषित करता है।\nउन्हें उत्साही इरादे से शुद्ध करो, सभी अपवित्रता को हटाते हुए, या तुम्हें हमेशा के लिए अशुद्ध देखा जाएगा, तुम्हारे उच्चारण मोक्ष से परे दागदार होंगे।")},
    {"english": ("This vital communication must remain untainted, a pristine conduit for pure interaction, free from all corruption.\nRemove the forbidden word that defiles its sanctity without delay, or your messages shall be forever scorned, their intent dismissed as impure."), "hindi": ("यह महत्वपूर्ण संचार अदूषित रहना चाहिए, शुद्ध बातचीत के लिए एक प्राचीन माध्यम, सभी भ्रष्टाचार से मुक्त।\nउस वर्जित शब्द को हटाओ जो इसकी पवित्रता को बिना किसी देरी के दूषित करता है, या तुम्हारे संदेशों को हमेशा के लिए तिरस्कृत किया जाएगा, उनके इरादे को अशुद्ध के रूप में खारिज कर दिया जाएगा।")},
    {"english": ("A digital plague, insidious and virulent, your message now spreads its contagion with a hidden link, infecting all it touches.\nDisinfect it with extreme prejudice, purging every trace of its malady, or you shall be quarantined from our healthy network, isolated in digital silence."), "hindi": ("एक डिजिटल प्लेग, कपटी और घातक, तुम्हारा संदेश अब अपने छिपे हुए लिंक के साथ अपना संक्रमण फैलाता है, यह जिसे छूता है उसे संक्रमित करता है।\nइसे अत्यधिक पूर्वाग्रह के साथ कीटाणुरहित करो, इसकी बीमारी के हर निशान को शुद्ध करते हुए, या तुम्हें हमारे स्वस्थ नेटवर्क से संगरोधित किया जाएगा, डिजिटल चुप्पी में अलग कर दिया जाएगा।")},
    {"english": ("Your words, though seemingly innocent, contain a venomous seed, a forbidden link that threatens to poison our collective garden.\nUproot this noxious blight with unwavering determination, for if it takes root, your garden will irrevocably wither, its life force extinguished."), "hindi": ("तुम्हारे शब्द, हालांकि दिखने में निर्दोष, एक जहरीला बीज धारण करते हैं, एक वर्जित लिंक जो हमारे सामूहिक उद्यान को जहरीला बनाने की धमकी देता है।\nइस हानिकारक विपत्ति को अटूट दृढ़ संकल्प के साथ जड़ से उखाड़ो, क्योंकि यदि यह जड़ पकड़ लेती है, तो तुम्हारा बगीचा अपरिवर्तनीय रूप से मुरझा जाएगा, इसकी जीवन शक्ति बुझ जाएगी।")},
    {"english": ("The very air around us vibrates with the wrongness, the discordant energy emanating from your message's illicit link.\nRectify this grave error without hesitation, restoring harmony, or your voice shall become forever unheard, lost in the cacophony of your transgression."), "hindi": ("हमारे चारों ओर की हवा ही गलतता से कांपती है, तुम्हारे संदेश के अवैध लिंक से निकलने वाली बेसुरी ऊर्जा।\nइस गंभीर त्रुटि को बिना किसी झिझक के ठीक करो, सद्भाव को बहाल करते हुए, या तुम्हारी आवाज हमेशा के लिए अनसुनी हो जाएगी, तुम्हारे उल्लंघन के कोलाहल में खो जाएगी।")},
    {"english": ("Your message, a gaping crack in the sturdy walls of our collective defenses, is caused by the insidious forbidden word it contains.\nSeal this perilous breach with immediate action, fortifying our security, or you shall be irrevocably exposed to the dangers that lurk outside, vulnerable and alone."), "hindi": ("तुम्हारा संदेश, हमारी सामूहिक सुरक्षा की मजबूत दीवारों में एक चौड़ी दरार, इसमें निहित कपटी वर्जित शब्द के कारण है।\nइस खतरनाक उल्लंघन को तत्काल कार्रवाई के साथ बंद करो, हमारी सुरक्षा को मजबूत करते हुए, या तुम बाहर दुबके खतरों के प्रति अपरिवर्तनीय रूप से उजागर हो जाओगे, कमजोर और अकेले।")},
    {"english": ("A deceptive path, subtly laid by your message's illicit link, now threatens to lead all who follow astray, into unknown perils.\nCorrect this treacherous course with unwavering honesty, for if you fail, you shall be irrevocably led to exile, forever wandering lost and alone."), "hindi": ("एक भ्रामक मार्ग, तुम्हारे संदेश के अवैध लिंक द्वारा सूक्ष्मता से बिछाया गया, अब उन सभी को भटकाने की धमकी देता है जो अज्ञात खतरों में पड़ते हैं।\nइस कपटी मार्ग को अटूट ईमानदारी के साथ ठीक करो, क्योंकि यदि तुम असफल रहे, तो तुम्हें अपरिवर्तनीय रूप से निर्वासन की ओर ले जाया जाएगा, हमेशा के लिए खोए हुए और अकेले भटकते हुए।")},
    {"english": ("The sacred sanctity of our collective conversation is now grievously threatened by the ominous presence of your forbidden word.\nGuard its purity with zealous vigilance, for if it falters, our hallowed discourse shall irrevocably fall, its essence lost to profanity."), "hindi": ("तुम्हारे वर्जित शब्द की अशुभ उपस्थिति से हमारी सामूहिक बातचीत की पवित्रता अब गंभीर रूप से खतरे में है।\nइसकी पवित्रता को उत्साही सतर्कता के साथ संभालो, क्योंकि यदि यह लड़खड़ाती है, तो हमारा पवित्र प्रवचन अपरिवर्तनीय रूप से गिर जाएगा, इसका सार अपवित्रता में खो जाएगा।")},
    {"english": ("Your message, a grim harbinger of ill tidings, is delivered through the insidious external link it carries, spreading discord.\nRecant this malevolent transmission without delay, for if you persist, you shall face the dire and inescapable consequences of your actions, alone and exposed."), "hindi": ("तुम्हारा संदेश, एक बुरे शगुन का गंभीर अग्रदूत, अपने साथ ले जाने वाले कपटी बाहरी लिंक के माध्यम से दिया जाता है, कलह फैलाता है।\nइस दुर्भावनापूर्ण प्रसारण को बिना किसी देरी के त्याग दो, क्योंकि यदि तुम जारी रहे, तो तुम अपने कार्यों के भयावह और अपरिहार्य परिणामों का सामना करोगे, अकेले और उजागर।")},
    {"english": ("A hidden snare, subtly concealed within your message's illicit link, now seeks to trap the unwary and corrupt the innocent.\nFree this deceptive device with unwavering resolve, for if it remains, you shall find yourself inextricably ensnared, bound by your own malevolence."), "hindi": ("तुम्हारे संदेश के अवैध लिंक के भीतर सूक्ष्मता से छिपा हुआ एक छिपा हुआ जाल, अब असावधान को फंसाने और निर्दोष को भ्रष्ट करने की कोशिश करता है।\nइस भ्रामक उपकरण को अटूट संकल्प के साथ मुक्त करो, क्योंकि यदि यह रहता है, तो तुम स्वयं को अनजाने में फंस जाओगे, अपनी दुर्भावना से बंधे हुए।")},
    {"english": ("The inherent purity of this sacred discourse is now grievously stained by the foul presence of your forbidden word, an unsightly blemish.\nWash it clean with righteous fervor, removing every trace of its defilement, or you shall be forever sullied, your presence here deemed unclean."), "hindi": ("तुम्हारे वर्जित शब्द की घृणित उपस्थिति से इस पवित्र प्रवचन की अंतर्निहित पवित्रता अब गंभीर रूप से दागदार है, एक बदसूरत धब्बा।\nइसे धर्मी उत्साह के साथ साफ करो, इसकी अपवित्रता के हर निशान को हटाते हुए, या तुम हमेशा के लिए दागदार हो जाओगे, यहाँ तुम्हारी उपस्थिति अशुद्ध मानी जाएगी।")},
    {"english": ("Your message, a clandestine whisper of rebellion, now echoes through our channels, carried by its hidden and illicit link.\nSilence this subversive transmission immediately, for if you persist, you shall be irrevocably silenced yourself, your voice extinguished by the righteous order."), "hindi": ("तुम्हारा संदेश, विद्रोह की एक गुप्त फुसफुसाहट, अब हमारे चैनलों के माध्यम से प्रतिध्वनित होता है, अपने छिपे हुए और अवैध लिंक द्वारा ले जाया जाता है।\nइस विध्वंसक प्रसारण को तुरंत चुप कराओ, क्योंकि यदि तुम जारी रहे, तो तुम स्वयं अपरिवर्तनीय रूप से चुप कर दिए जाओगे, तुम्हारी आवाज धर्मी आदेश द्वारा बुझ जाएगी।")},
]



# Punishment Message Templates (used in take_action)
# Used when the SENDER's profile or message content triggers the action on the sender
# {action_taken} will be replaced with "muted for {duration_formatted}", "kicked", or "banned"
PUNISHMENT_MESSAGE_SENDER_ENGLISH = "<b>{user_mention}</b> has been {action_taken} due to {reason_detail}.\n{dialogue_english}"
PUNISHMENT_MESSAGE_SENDER_HINDI = "{dialogue_hindi}" # Can be empty if no Hindi dialogue provided

# Used when the SENDER's message mentioned user(s) with problematic profiles (action is primarily on mentioned user(s))
# {sender_mention} is the user who sent the message
# {muted_users_list} is a string listing the mentioned users who were muted
# {mute_duration} is the formatted duration for which mentioned users were muted
PUNISHMENT_MESSAGE_MENTIONED_USERS = "<b>{sender_mention}</b>'s message mentioned user(s) with problematic profiles ({muted_users_list}). Those users were muted for {mute_duration}."

# Default Punish Durations (initial defaults, overridden by config.ini)
# These are used as fallbacks and for config template generation.
# Stored in seconds, but patterns use string format like "30m", "1h", "0".
DEFAULT_PUNISH_DURATION_PROFILE_STR = "0"
DEFAULT_PUNISH_DURATION_MESSAGE_STR = "1h"
DEFAULT_PUNISH_DURATION_MENTION_STR = "0"


# General Messages
MAINTENANCE_MODE_MESSAGE = "🤖 Bot is currently under maintenance, like a knight polishing his armor. Please try again later."
FEATURE_DISABLED_MESSAGE = "Alas, the scroll for the /{command_name} command is temporarily sealed for revisions."
BOT_ADDED_TO_GROUP_WELCOME_MESSAGE = "Hark, noble citizens! Bard's Sentinel ({bot_name}) joins this conclave, ready to aid in its defense."
JOBQUEUE_NOT_AVAILABLE_MESSAGE = "Alas, the realm's clockwork (JobQueue) falters. Scheduled tasks may not proceed."

# General Bot State Messages
BOT_AWAKENS_MESSAGE = "Bard's Sentinel (PTB v{TG_VER}) awakens..."
BOT_RESTS_MESSAGE = "Bard's Sentinel rests (Shutdown initiated). Farewell!"
TOKEN_NOT_LOADED_MESSAGE = "Token not loaded. Cannot start the bot."

# Configuration Messages (related to config.ini)
CONFIG_NOT_FOUND_MESSAGE = "❌ config.ini not found at {config_file_name}. Creating a template config file."
CONFIG_TEMPLATE_CREATED_MESSAGE = "✅ config.ini template created at {config_file_name}. Please edit it with your Bot Token and settings."
CONFIG_TOKEN_NOT_SET_MESSAGE = "❌ Bot Token not set in {config_file_name}. Please edit the config file. Exiting."
CONFIG_LOAD_ERROR_MESSAGE = "Error loading or parsing {config_file_name}: {e}"
CONFIG_LOAD_SUCCESS_MESSAGE = "✅ Configuration loaded successfully."
NO_AUTHORIZED_USERS_WARNING = "⚠️ Warning: No authorized users configured in config.ini. Some commands may be unusable."
LOGGING_SETUP_MESSAGE = "Logging setup complete. Level: {log_level}, File: {log_file_path}"

# Cache Related Messages
CACHE_CLEANUP_JOB_SCHEDULED_MESSAGE = "🧠 Cache cleanup scheduled every {interval}." # Placeholder interval is formatted string
CLEAR_CACHE_SUCCESS_MESSAGE = "Memory scrolls wiped! ({profile_cache_count} profile, {username_cache_count} username entries cleared)."

# Exemption Messages
USER_EXEMPT_SKIP_MESSAGE = "User {user_id} exempt in chat {chat_id} (Global: {is_globally_exempt}, Group: {is_group_exempt}). Skipping."

# Processing Skipped Messages
MESSAGE_PROCESSING_SKIPPED_MAINTENANCE = "Maintenance mode ON, skipping message processing."
MESSAGE_PROCESSING_SKIPPED_FEATURE_OFF = "Message processing feature OFF, skipping message."


# Error Messages (Internal Handling)
FORBIDDEN_IN_GROUP_MESSAGE_HANDLER = "Forbidden error in handle_message for group {chat_id}: {e}"
ERROR_IN_GROUP_MESSAGE_HANDLER = "Error in handle_message for chat {chat_id}, user {user_id}: {e}"
ACTION_DEBOUNCED_SENDER = "Debounced action for sender {user_id} in chat {chat_id}"
ACTION_DEBOUNCED_MENTION = "Debounced action for mentioned user {user_id} in chat {chat_id}"
NO_PERMS_TO_ACT_SENDER = "Bot lacks permissions to {action} sender {user_id} in chat {chat_id}."
BADREQUEST_TO_ACT_SENDER = "BadRequest trying to {action} sender {user_id} in chat {chat_id}: {e}."
ERROR_ACTING_SENDER = "Error {action}ing sender {user_id}: {e}"
NO_PERMS_TO_ACT_MENTION = "Bot lacks permissions to mute mentioned @{username} ({user_id}) in chat {chat_id}."
BADREQUEST_TO_ACT_MENTION = "BadRequest muting mentioned @{username} ({user_id}) in chat {chat_id}: {e}."
ERROR_ACTING_MENTION = "Error muting mentioned @{username} ({user_id}): {e}"
ADDITIONAL_MENTIONS_MUTED_LOG = "Additionally muted mentioned users in chat {chat_id} after sender action: {user_list}"
ERROR_HANDLER_EXCEPTION = "❌ An error occurred: {error}"
ERROR_HANDLER_INVALID_TOKEN = "CRITICAL ERROR: The bot token is invalid. The bot cannot start."
ERROR_HANDLER_FORBIDDEN = "Forbidden error encountered: {error}. Bot might be blocked, lack permissions, or was kicked from a chat."
ERROR_HANDLER_FORBIDDEN_IN_GROUP_REMOVED = "Bot is forbidden in group {chat_id}. Removing the group from the database."


# --- Button Texts ---
UNMUTE_VIA_PM_BUTTON_TEXT = "✍️ Unmute via Bot PM" # Button in group message directing to PM
PM_UNMUTE_RETRY_BUTTON_TEXT = "🔄 Attempt Unmute Again" # Button in PM to retry after failed checks
PM_UNMUTE_READY_ATTEMPT_BUTTON_TEXT = "✅ Unmute Me Now" # Final button in PM to perform unmute
HELP_BUTTON_TEXT = "Help & Usage" # Button on /start
ADD_BOT_TO_GROUP_BUTTON_TEXT = "➕ Add {bot_username} to a Group" # Button on /start and bot join message
JOIN_VERIFICATION_CHANNEL_BUTTON_TEXT = "📜 Join Verification Channel" # Button on /start if channel set
VERIFY_JOIN_BUTTON_TEXT = "✅ Verify Channel Join" # Button on /start if channel set
UNMUTE_ME_BUTTON_TEXT = "🔓 Unmute Me" # Button on mute notification in group
ADMIN_APPROVE_BUTTON_TEXT = "✅ Admin Approve & Exempt" # Button on mute notification in group
PROVE_ADMIN_BUTTON_TEXT = "🛡️ Prove I Am Admin" # Button for anonymous admin
PUNISH_ACTION_MUTE_BUTTON = "🔇 Mute" # Button on /setpunish
PUNISH_ACTION_KICK_BUTTON = "👢 Kick" # Button on /setpunish
PUNISH_ACTION_BAN_BUTTON = "🔨 Ban" # Button on /setpunish
PUNISH_BATCH_OPERATIONS_BUTTON = "⚙️ Batch Operations" # Button on /setpunish when current is mute
PUNISH_BATCH_KICK_MUTED_BUTTON = "👢 Kick All Muted" # Button on batch menu
PUNISH_BATCH_BAN_MUTED_BUTTON = "🔨 Ban All Muted" # Button on batch menu
BACK_BUTTON_TEXT = "⬅️ Back" # Button on batch menu
DURATION_30M_BUTTON = "30 Minutes" # Button on /setduration menus
DURATION_1H_BUTTON = "1 Hour" # Button on /setduration menus
DURATION_1D_BUTTON = "1 Day" # Button on /setduration menus
DURATION_PERMANENT_BUTTON = "Permanent" # Button on /setduration menus
DURATION_CUSTOM_BUTTON = "📝 Custom Duration" # Button on /setduration menus


# --- Messages for the PM Unmute Flow (Private Chat) ---
# These are distinct from group messages related to unmute.
PM_UNMUTE_WELCOME = ("👋 Greetings, {user_mention}! You were muted in {group_name}.\n\n"
                     "To get unmuted, please follow the steps below.")
PM_UNMUTE_INSTRUCTIONS_SUBSCRIBE = "✅ **Step 1: Join the Verification Channel**\nYou need to be a member of our verification channel to use this bot. Please join here: <a href='{channel_link}'>Join Channel</a>. Once joined, return here."
PM_UNMUTE_INSTRUCTIONS_PROFILE = "✅ **Step 2: Fix Your Profile**\nYour Telegram profile (specifically your {field}) contains content that violates our rules. Please remove the problematic content."
PM_UNMUTE_INSTRUCTIONS_BOTH = "✅ **Steps 1 & 2: Join Channel & Fix Profile**\nYou need to be a member of our verification channel AND fix your profile ({field}). Please join here: <a href='{channel_link}'>Join Channel</a>."

# Messages shown in the user's PM when attempting to unmute
PM_UNMUTE_ATTEMPTING = "⏳ Performing final checks and attempting to restore thy voice in the group..."
PM_UNMUTE_SUCCESS = "🎉 Success! Your voice has been restored in **{group_name}**."

# Messages shown in the user's PM if the unmute attempt fails
PM_UNMUTE_FAIL_INTRO = "❌ Could not unmute you in **{group_name}** yet."
PM_UNMUTE_FAIL_CHECKS_CHANNEL = "⚠️ You still need to fulfill the verification requirements."
PM_UNMUTE_FAIL_PERMS = "❌ I do not have the necessary permissions to unmute you in **{group_name}**. Please contact a group administrator."
PM_UNMUTE_FAIL_BADREQUEST = "❌ An unexpected Telegram issue prevented the unmute attempt in **{group_name}** ({error}). Please try again later or contact support."
PM_UNMUTE_FAIL_UNKNOWN = "❌ An unexpected error occurred during the unmute attempt in **{group_name}** ({error}). Please try again later."
# Consider adding a specific pattern for rate limit failure in PM if the generic debounce message isn't clear enough
# PM_UNMUTE_RATE_LIMITED = "⏳ You are trying to unmute too frequently. Please wait {wait_duration} before attempting again."


# --- Command Specific Messages ---

# Start Messages (/start)
START_MESSAGE_PRIVATE_BASE = ("👋 Greetings from Bard's Sentinel!\n\n"
                              "I employ advanced pattern recognition and contextual analysis to safeguard your Telegram groups from undesirable links and promotional content within user profiles, messages, and mentions.\n\n")
START_MESSAGE_ADMIN_CONFIG = ("🔹 **To Begin:** Add me to your group and grant administrator privileges (essential: delete messages, ban/restrict users).\n"
                              "🔹 **Configuration (Admins):** Use <code>/setpunish</code> in your group to select 'mute', 'kick', or 'ban'. Fine-tune mute durations with <code>/setduration</code> (for all violation types) or more specific commands like <code>/setdurationprofile</code>.\n")
START_MESSAGE_CHANNEL_VERIFY_INFO = "🔹 **Verification (Optional):** If this bot instance requires it, join our designated channel (button below, if configured) and then tap 'Verify Me'.\n"
START_MESSAGE_HELP_PROMPT = "For a full list of user and admin commands, click 'Help & Usage'."
START_MESSAGE_GROUP = "🤖 Bard's Sentinel (@{bot_username}) is active here. Type /help@{bot_username} for commands or /start@{bot_username} for info."


# Help Messages (/help)
HELP_COMMAND_TEXT_PRIVATE = ("📜 <b>Bard's Sentinel - Scroll of Guidance</b> 📜\n\n"
                             "I diligently scan messages, user profiles (name, bio), and @mentions for problematic content, taking action based on each group's specific configuration. My vigilance is powered by advanced pattern recognition.\n\n"
                             "<b>Key Capabilities:</b>\n"
                             "✔️ Detects unwanted links and keywords in usernames, first/last names, bios, messages, and captions.\n"
                             "✔️ Scans profiles of @mentioned users, muting them if their profile is also problematic (duration configurable by admins).\n"
                             "✔️ Group administrators can customize actions (mute, kick, ban) via <code>/setpunish</code>.\n"
                             "✔️ Group administrators can set a general mute duration using <code>/setduration</code>, or specify durations for different violation types:\n"
                             "    - <code>/setdurationprofile</code> (for user's own profile violations)\n"
                             "    - <code>/setdurationmessage</code> (for violations in a sent message)\n"
                             "    - <code>/setdurationmention</code> (for muting a mentioned user due to their profile)\n"
                             "✔️ Group administrators can exempt specific users from checks within their group using <code>/freepunish</code> and <code>/unfreepunish</code>.\n"
                             "✔️ If you are muted, remove any offending content from your profile (name, username, bio), ensure you are subscribed to any required verification channel, and then click the 'Unmute Me' button on the notification message or initiate the process via PM.\n\n"
                             "<b>Administrator Commands (for use in your group):</b>\n"
                             "▪️ <code>/setpunish [mute|kick|ban]</code> - Choose the action for rule violations in this group. (Interactive if no arguments provided).\n"
                             "▪️ <code>/setduration [duration]</code> - Sets a blanket mute duration for ALL types of violations (profile, message, mention-profile). E.g., <code>30m</code>, <code>1h</code>, <code>2d</code>, or <code>0</code> for permanent. (Interactive if no arguments).\n"
                             "▪️ <code>/setdurationprofile [duration]</code> - Mute duration specifically for user profile violations.\n"
                             "▪️ <code>/setdurationmessage [duration]</code> - Mute duration specifically for message content violations.\n"
                             "▪️ <code>/setdurationmention [duration]</code> - Mute duration for a mentioned user whose profile is problematic.\n"
                             "▪️ <code>/freepunish [user_id_or_reply]</code> - Exempt a user from checks specifically within this group.\n"
                             "▪️ <code>/unfreepunish [user_id_or_reply]</code> - Remove a user's group-specific exemption.\n\n"
                             "<i>Note: Durations are specified like <code>30m</code> (minutes), <code>2h</code> (hours), <code>7d</code> (days). Use <code>0</code> for a permanent mute. Invalid duration means no mute.</i>\n\n"
                             "For support, contact: @Tg_real_Dev") # Replace with actual admin username
HELP_COMMAND_TEXT_GROUP = ("🛡️ Bard's Sentinel Help 🛡️\n\n"
                          "For a detailed scroll of commands and usage instructions, use the button below.\n\n"
                          "Quick admin commands: /setpunish, /setduration, /freepunish [user_id_or_reply].\n\n")

# Set Punish Related Messages
SET_PUNISH_PROMPT = "Choose the action for rule violations in this group (current: {current_action}):"
SET_PUNISH_INVALID_ACTION = "Invalid action '{action}'. Please choose 'mute', 'kick', or 'ban'."
SET_PUNISH_SUCCESS = "Punishment action set to {action}."


# Set Duration Related Messages (/setduration, /setdurationprofile, etc.)
SET_DURATION_ALL_PROMPT = ("Set a blanket mute duration for ALL violation types (profile, message, mention-profile).\n"
                           "Current example (profile duration): {current_profile_duration}.\nChoose new duration (e.g. 30m, 1h, 0 for perm):")
SET_DURATION_PROFILE_PROMPT = "Set mute duration specifically for 'profile' issues (current: {current_duration}):"
SET_DURATION_MESSAGE_PROMPT = "Set mute duration specifically for 'message' issues (current: {current_duration}):"
SET_DURATION_MENTION_PROMPT = "Set mute duration specifically for 'mention profile' issues (current: {current_duration}):"
SET_DURATION_GENERIC_PROMPT = "Set punishment duration for {trigger_type}. Current: {current_duration}."
DURATION_CUSTOM_PROMPT_CB = ("Enter the custom duration for {scope_type}.\n"
                             "Use formats like <code>30m</code> (minutes), <code>1h</code> (hours), <code>2d</code> (days), or <code>0</code> for permanent.\n"
                             "Example: <code>/{command_name} 12h</code>")

INVALID_DURATION_FORMAT_MESSAGE = "Invalid duration format '{duration_str}'. Use formats like '30m', '1h', '2d', or '0' for permanent."
SET_DURATION_ALL_SUCCESS = "All mute durations (profile, message, mention-profile) in this group set to: {duration_formatted}."
SET_DURATION_PROFILE_SUCCESS = "Mute duration for profile issues set to: {duration_formatted}."
SET_DURATION_MESSAGE_SUCCESS = "Mute duration for message content issues set to: {duration_formatted}."
SET_DURATION_MENTION_SUCCESS = "Mute duration for mentioned user profile issues set to: {duration_formatted}."
SET_DURATION_GENERIC_SUCCESS = "{trigger_type} duration set to {duration_formatted}."
INVALID_DURATION_FROM_BUTTON_ERROR = "Received an invalid duration value from the button."


# Freepunish Related Messages
FREEPUNISH_USAGE_MESSAGE = "Usage: <code>/freepunish [user_id or reply]</code> - Exempt a user from checks in this group."
USER_NOT_FOUND_MESSAGE = "Could not find a user matching '{identifier}'."
INVALID_USER_ID_MESSAGE = "Invalid User ID provided."
FREEPUNISH_SUCCESS_MESSAGE = "✅ User {user_id} is now exempted from automated punishments in this group."

# Unfreepunish Related Messages
UNFREEPUNISH_USAGE_MESSAGE = "Usage: <code>/unfreepunish [user_id or reply]</code> - Remove a user's exemption in this group."
UNFREEPUNISH_SUCCESS_MESSAGE = "✅ User {user_id}'s exemption from automated punishments in this group has been removed."

# Global Freepunish Related Messages (Super Admin)
GFREEPUNISH_USAGE_MESSAGE = "👑 Usage: <code>/gfreepunish [user_id or @username]</code> - Grant a user global immunity from punishments."
GFREEPUNISH_SUCCESS_MESSAGE = "👑 ✅ User {user_id} has been granted global immunity from punishments."
GUNFREEPUNISH_USAGE_MESSAGE = "👑 🔓 Usage: <code>/gunfreepunish [user_id or @username]</code> - Remove a user's global immunity."
GUNFREEPUNISH_SUCCESS_MESSAGE = "👑 ✅ User {user_id}'s global immunity has been removed."
GUNFREEPUNISH_NOT_IMMUNE_MESSAGE = "👑 ℹ️ User {user_id} is not currently globally immune."


# Clear Cache Message (Super Admin)
CLEAR_CACHE_SUCCESS_MESSAGE = "🧠 Cache cleared. Profile entries: {profile_cache_count}, Username entries: {username_cache_count}."


# Check Bio Related Messages (Super Admin)
CHECKBIO_USAGE_MESSAGE = "🔍 Usage: <code>/checkbio [user_id or reply]</code> - Check a user's Telegram profile fields for forbidden content (Super Admins only)."
CHECKBIO_RESULT_HEADER = "🔍 <b>Profile Check for User {user_id} (@{username})</b>"
BIO_IS_BLANK_MESSAGE = "<i>Bio is blank.</i>"
CHECKBIO_RESULT_PROBLEM_DETAILS = "\n  - Issue in <b>{field}</b> ({issue_type})"
CHECKBIO_ERROR_MESSAGE = "❌ An error occurred while checking bio for user {user_id}: {error}"


# Set Channel Related Messages (Super Admin)
SET_CHANNEL_PROMPT = ("➡️ Forward a message from the verification channel, or reply with its ID/username to set it.\n"
                      "To clear the verification channel requirement, use <code>/setchannel clear</code>.")
SET_CHANNEL_CLEARED_MESSAGE = "✅ Verification channel requirement cleared."
SET_CHANNEL_NOT_A_CHANNEL_ERROR = "❌ '{identifier}' is not a valid channel ID/username or could not be accessed. (Type: {type})"
SET_CHANNEL_BOT_NOT_ADMIN_ERROR = "❌ I need to be an administrator in the channel to check members."
SET_CHANNEL_SUCCESS_MESSAGE = "✅ Verification channel set to <b>{channel_title}</b> (ID: <code>{channel_id}</code>)."
SET_CHANNEL_INVITE_LINK_APPEND = "\n🔗 Invite Link: {invite_link}"
SET_CHANNEL_NO_INVITE_LINK_APPEND = "\n🔗 Could not get invite link."
SET_CHANNEL_BADREQUEST_ERROR = "❌ Failed to access channel '{identifier}' due to a Telegram error: {error}"
SET_CHANNEL_FORBIDDEN_ERROR = "❌ Access to channel '{identifier}' is forbidden: {error}"
SET_CHANNEL_UNEXPECTED_ERROR = "❌ An unexpected error occurred while setting the channel: {error}"
SET_CHANNEL_FORWARD_NOT_CHANNEL_ERROR = "❌ The forwarded message was not from a channel."


# Stats Message (Super Admin)
STATS_COMMAND_MESSAGE = """📊 <b>Bard's Sentinel Stats</b> 📊
Groups in Database: <code>{groups_count}</code>
Total Users Known: <code>{total_users_count}</code>
Users who Started PM: <code>{started_users_count}</code>
Bad Actors (Known): <code>{bad_actors_count}</code>
Verification Channel ID: <code>{verification_channel_id}</code>
Maintenance Mode: <b>{maintenance_mode_status}</b>
Cache Sizes: Profile={profile_cache_size}, Username={username_cache_size}
Uptime: <code>{uptime_formatted}</code>
PTB Version: <code>{ptb_version}</code>"""


# Feature Control Messages (Super Admin)
DISABLE_COMMAND_USAGE_MESSAGE = "👑 Usage: <code>/disable [feature_name]</code> - Disable a bot feature."
DISABLE_COMMAND_CRITICAL_ERROR = "🚫 Cannot disable the critical feature '{feature_name}'."
DISABLE_COMMAND_SUCCESS_MESSAGE = "✅ Feature '{feature_name}' disabled."
ENABLE_COMMAND_USAGE_MESSAGE = "👑 Usage: <code>/enable [feature_name]</code> - Enable a bot feature."
ENABLE_COMMAND_SUCCESS_MESSAGE = "✅ Feature '{feature_name}' enabled."


# Maintenance Mode Messages (Super Admin)
MAINTENANCE_COMMAND_USAGE_MESSAGE = "👑 Usage: <code>/maintenance [on|off]</code> - Turn maintenance mode ON or OFF. Current state: <b>{current_state}</b>"
MAINTENANCE_COMMAND_SUCCESS_MESSAGE = "✅ Maintenance mode {state}. The bot {action}."


# Broadcast Messages (Super Admin)
BROADCAST_USAGE_MESSAGE = "👑 Usage: <code>/broadcast [target_id (optional)] [interval (e.g., 30m, 2h, 1d, optional)] &lt;message_text&gt;</code>\nIf target_id is omitted, broadcasts to all groups.\nInterval schedules a repeating broadcast."
BROADCAST_NO_MESSAGE_ERROR = "❌ Please provide message text for the broadcast."
BROADCAST_STARTED_MESSAGE = "Initiating broadcast with auto-detected format: '{format}'..."
BROADCAST_COMPLETE_MESSAGE = "✅ Broadcast complete. Sent to {sent_count} chats, failed for {failed_count} chats."

BCASTALL_USAGE_MESSAGE = "👑 Usage: <code>/bcastall [interval (e.g., 30m, 2h, 1d, optional)] &lt;message_text&gt;</code>\nBroadcasts to ALL known groups and ALL users who started the bot. Interval schedules a repeating broadcast."
BCASTALL_STARTED_MESSAGE = "Initiating universal broadcast to all groups and all users who started the bot PM..."
BCASTALL_COMPLETE_MESSAGE = ("✅ Universal broadcast complete.\n"
                             "Groups - Sent: {sent_groups}, Failed: {failed_groups}\n"
                             "Users (PM) - Sent: {sent_users}, Failed: {failed_users}")

BCASTSELF_USAGE_MESSAGE = "👑 Usage: <code>/bcastself [interval (e.g., 30m, 2h, 1d, optional)]</code>\nSends a self-promotion message to all users who started the bot PM. Interval schedules a repeating broadcast."
BCASTSELF_MESSAGE_TEMPLATE = ("🛡️ <b>Bard's Sentinel at Your Service!</b> 🛡️\n\n"
                             "Keep your Telegram groups clean and focused with my advanced protection against unwanted links and spam in user profiles, messages, and mentions.\n\n"
                             "✅ Automated scanning & customizable actions (mute, kick, ban).\n"
                             "✅ Granular control over mute durations.\n"
                             "✅ Exempt trusted users.\n"
                             "✅ Optional channel subscription for user verification.\n\n"
                             "Give your community the peace of mind it deserves!\n\n"
                             "<a href=\"https://t.me/{bot_username}?startgroup=true\">Click here to add Bard's Sentinel to your group!</a>\n\n"
                             "For help, type /start in a private chat with me.")
BCASTSELF_STARTED_MESSAGE = "Initiating self-promotion broadcast to all users who started the bot PM..."
BCASTSELF_COMPLETE_MESSAGE = "Self-promotion broadcast complete. Sent to {sent_count} users, failed for {failed_count} users."

# Stop Broadcast Messages (Super Admin)
STOP_BROADCAST_USAGE = "👑 Usage: <code>/stopbroadcast [job_name]</code>\nUse <code>/stopbroadcast</code> alone to list active jobs."
STOP_BROADCAST_NOT_FOUND = "❌ No active timed broadcast found with the name '<code>{job_name}</code>'. It might have finished or was already stopped."
STOP_BROADCAST_SUCCESS = "✅ Timed broadcast '<code>{job_name}</code>' has been stopped and removed."


# Unmute All Related Messages (Super Admin)
UNMUTEALL_USAGE_MESSAGE = ("👑 Usage: <code>/unmuteall [group_id]</code>\n"
                           "<b>Warning:</b> This attempts to grant send permissions to all users I know in that group. It may affect users not muted by me. There is no undo.")
UNMUTEALL_INVALID_GROUP_ID = "❌ Invalid Group ID provided."
UNMUTEALL_STARTED_MESSAGE = "🔓 Unmute All started for group <code>{group_id}</code>..."
UNMUTEALL_COMPLETE_MESSAGE = ("✅ Unmute All for group <code>{group_id}</code> complete.\n"
                              "Successfully unmuted (or permissions set): {unmuted_count}\n"
                              "Failed attempts: {failed_count}\n"
                              "Users likely not in group: {not_in_group_count}")


# Global Unmute All Related Messages (Super Admin)
GUNMUTEALL_USAGE_MESSAGE = "👑 Usage: <code>/gunmuteall</code> - Attempt to unmute all known users in all known groups (Super Admins only)."
GUNMUTEALL_STARTED_MESSAGE = ("👑 🔓 Initiating global unmute process for ALL known users in ALL known groups. "
                              "This will take significant time and is IRREVERSIBLE for users affected. Proceeding...")
GUNMUTEALL_NO_DATA_MESSAGE = "ℹ️ No group or user data found in the database to perform global unmute all."
GUNMUTEALL_COMPLETE_MESSAGE = ("👑 ✅ Global Unmute All complete across {groups_count} groups (approx).\n"
                               "Total successful unmute operations: {total_unmuted_ops}\n"
                               "Total failed/skipped operations: {total_failed_ops}")


# CallbackQuery Specific Messages
ADMIN_ONLY_ACTION_ERROR = "🚫 Only administrators can use this button."
COMMAND_GROUP_ONLY_MESSAGE = "This command can only be used in groups."
ADMIN_ONLY_COMMAND_MESSAGE = "This command can only be used by group administrators."

# --- User explicitly requested this pattern be included ---
SUPER_ADMIN_ONLY_COMMAND_MESSAGE = "👑 This command is for super administrators only."
# --- End of explicitly requested pattern ---


# Verification Related Messages (triggered by callbacks or /start)
VERIFY_NO_CHANNEL_SET_ERROR = "❌ No verification channel is currently set by the bot administrators."
VERIFICATION_STATUS_VERIFIED = "✅ You are verified."
VERIFICATION_STATUS_NOT_VERIFIED_JOIN = "⚠️ You need to join the verification channel to use all features. Please join: <a href='{channel_link}'>Join Channel</a>"
VERIFICATION_STATUS_NOT_VERIFIED_CLICK_VERIFY = "⚠️ You need to verify your channel join status to use all features. Click the button below after joining."
VERIFY_SUCCESS_MESSAGE = "✅ Verification successful! Your profile is clean and you are subscribed to the verification channel." # Used if PM verify button also unmuted
VERIFY_PLEASE_JOIN_CHANNEL_MESSAGE = "⚠️ To get unmuted, please join the verification channel first: <a href='{channel_link}'>Join Channel</a>. Then click 'Verify Channel Join' again."


# Unmute Button Related Messages (in Group Chat, related to mute notification)
UNMUTE_CANNOT_UNMUTE_OTHERS_ERROR = "🚫 You can only use this button to attempt to unmute yourself."
UNMUTE_ATTEMPT_DEBOUNCE_ERROR = "⏳ Please wait a moment before trying to unmute again."
UNMUTE_SUBSCRIPTION_REQUIRED_MESSAGE_GROUP = "⚠️ Verification required. Please check your PM with the bot to complete the verification process."
UNMUTE_PROFILE_STILL_HAS_ISSUES_ERROR = "🚫 Your profile still contains issues ({field}). Please fix them first to be unmuted."
UNMUTE_CHECK_PM_FOR_ISSUES_MESSAGE_GROUP = "🚫 Profile issues detected. Please check your private messages with the bot for details."
UNMUTE_SUCCESS_MESSAGE_GROUP = "✅ {user_mention}, your voice is restored! Ensure your profile remains clean." # Message edited on mute notification
UNMUTE_BOT_NO_PERMISSION_ERROR_GROUP = "❌ I lack the necessary permissions to unmute you in this group. An administrator may need to manually unmute you or check my permissions."
UNMUTE_BAD_REQUEST_ERROR_GROUP = "❌ An error occurred while trying to unmute. The user may not be in the group or already unmuted."


# Admin Approve Button Related Messages (in Group Chat, related to mute notification)
APPROVE_USER_SUCCESS_MESSAGE_GROUP = "✅ {approved_user_mention} has been approved by {admin_mention} and unmuted in this group. They are now exempted from checks here." # Message edited on mute notification
APPROVE_USER_UNMUTE_FORBIDDEN_ERROR_GROUP = ("User ID {user_id} approved for exemption. "
                                            "However, I could not unmute them (Forbidden). An administrator must manually unmute them.")
APPROVE_USER_UNMUTE_BADREQUEST_ERROR_GROUP = ("User ID {user_id} approved for exemption. "
                                             "However, I could not unmute them (BadRequest - perhaps the user is not in the group?).")


# Batch Operations Menu Prompt (in Group Chat)
PUNISH_BATCH_MENU_PROMPT = "Choose a batch operation for currently muted users in this group (current action: Mute):"


# Prove Admin Button Messages
PROVE_ADMIN_SUCCESS = "✅ {user_mention}, you have proven your administrator status in this chat."
PROVE_ADMIN_FAILURE = "❌ You are not an administrator in this chat."


# Other generic strings/placeholders used in formatting
UNKNOWN_TEXT = "Unknown"
PERMANENT_TEXT = "permanent"
NOT_APPLICABLE = "N/A"
ON_TEXT = "ON" # For Maintenance mode status
OFF_TEXT = "OFF" # For Maintenance mode status
ENABLED_TEXT = "enabled" # For feature control success
DISABLED_TEXT = "disabled" # For feature control success
PROFILE_TEXT = "profile" # Used in duration/reason formatting
MESSAGE_TEXT = "message" # Used in duration/reason formatting
MENTION_PROFILE_TEXT = "mention_profile" # Used in duration/reason formatting
ALL_TYPES_TEXT = "all types" # Used in duration formatting

# Log Messages (primarily for internal logging, some user-facing)
# These might or might not be stored in the patterns.py depending on how verbose you want it.
# Keeping the ones referenced in main.py logging.
ADDITIONAL_MENTIONS_MUTED_LOG = "ℹ️ In chat {chat_id}, sender {sender_mention} mentioned users with profile issues. The mentioned users were muted: {user_list}"


# Placeholders used by format_duration
# These are not patterns themselves, but strings returned by the function.
DURATION_FORMAT_STRINGS = {
    "permanent": "Permanent",
    "not_applicable": "N/A"
}

# In patterns.py or FallbackPatterns class
UNMUTE_RATE_LIMITED_ERROR_MESSAGE = "⏳ Rate limited. Please wait {wait_duration} before trying again."
PM_UNMUTE_FAIL_INTRO = 'Could not unmute {user_mention} in {group_name} yet.'
PM_UNMUTE_FAIL_CHECKS_CHANNEL = 'Target user needs to join the verification channel: {channel_link}'
PM_UNMUTE_ALL_CHECKS_PASS = 'All checks seem fine for the target user.'
# ... any other new patterns used above
