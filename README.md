# ☠ RTK — Red Team Kit v3.0

**RTK (Red Team Kit)** — yazılı icazəli təhlükəsizlik qiymətləndirmələri üçün Python əsaslı iş axınıdır:

**Passiv OSINT → Scope daxilində Recon → Finding idarəetməsi → CVSS v3.1 → HTML/SARIF hesabat**

- Python **3.8+**
- Python standard library-dən başqa məcburi paket yoxdur
- Windows, Linux və macOS-da CLI; terminalda interaktiv shell
- v2.x engagement qovluqlarındakı `scope.json` formatı ilə geriyə uyğun işləmək üçün nəzərdə tutulub

> **Hüquqi qeyd:** RTK yalnız sistem sahibinin yazılı icazəsi və təsdiqlənmiş scope daxilində istifadə olunmalıdır. Scope Guard texniki köməkçidir, hüquqi icazənin əvəzi deyil. OSINT mənbələrinin öz istifadə şərtlərinə və sorğu limitlərinə əməl edin.

## 1. Quraşdırma

Layihəni GitHub-dan klonlayın və qovluğa daxil olun:

```bash
git clone https://github.com/bahad1rl1umud/rtk.git
cd rtk
```

Python 3.8 və daha yeni versiya kifayətdir. Əsas CLI və hesabat modulları üçün əlavə Python paketi lazım deyil.

### Aktiv recon alətləri (opsional)

`recon` əmri aşağıdakı xarici alətləri mövcud olduqda çağırır:

| Alət | İstifadə |
|---|---|
| `subfinder` | Subdomain mənbələrinin toplanması |
| `httpx` | Hostların HTTP metadata yoxlaması |
| `nuclei` | Seçilmiş exposure template-ləri ilə yoxlama |
| `feroxbuster` | İstəyə bağlı content discovery |

Bu alətləri öz platformanızın rəsmi quraşdırma təlimatına əsasən quraşdırın və versiyalarını yoxlayın. Kali/Debian əsaslı sistemlərdə `seclists` wordlist paketi də istifadə oluna bilər.

**Qeyd:** `feroxbuster` v3.0-da standart olaraq işləmir. Onu yalnız ayrıca `--content-scan` parametrini verdikdə aktiv edin. Recon sorğu limiti standart olaraq saniyədə 5-dir; ehtiyac olduqda aşağı salın.

## 2. Sürətli başlanğıc

Bütün nümunələr yalnız sizə məxsus və ya yazılı icazə aldığınız `example.com` kimi test domeni üçündür.

### 2.1 Engagement yarat

```bash
python rtk-v3.0.py init acme-test -c "ACME Corp" -t example.com
```

Bir neçə domen və ya IP/CIDR daxil etmək mümkündür:

```bash
python rtk-v3.0.py init internal-lab -c "Internal Lab" -t "example.com,api.example.com,192.168.1.0/24"
```

Scope `scope.json` faylında saxlanılır. Domain scope həmin domeni və onun subdomainlərini əhatə edir. IP scope dəqiq IP ilə, CIDR isə həmin şəbəkə aralığındakı IP-lərlə uyğunlaşdırılır.

### 2.2 Passiv OSINT

```bash
python rtk-v3.0.py osint -e acme-test -t example.com
```

GitHub code search üçün opsional token:

```bash
python rtk-v3.0.py osint -e acme-test -t example.com --token YOUR_GITHUB_TOKEN
```

Tokeni paylaşmayın və kodun içinə yazmayın. OSINT nəticələri engagement qovluğunda `osint_<domain>.json` faylına yazılır.

Mənbələr:
- crt.sh — Certificate Transparency qeydləri
- Wayback Machine — arxivlənmiş URL-lər
- HackerTarget — host axtarışı
- GitHub API — repository/user axtarışı; token olduqda code search
- LinkedIn/Google/Bing dork linkləri — brauzerdə manual baxış üçün

Mənbə əlçatan olmadıqda RTK xəta qeyd edir və digər mənbələrə davam edir.

### 2.3 Recon

```bash
python rtk-v3.0.py recon -e acme-test -t example.com
```

Sorğu limitini və timeout-u dəyişmək:

```bash
python rtk-v3.0.py recon -e acme-test -t example.com --rate-limit 3 --timeout 600
```

Content discovery-ni ayrıca aktiv etmək:

```bash
python rtk-v3.0.py recon -e acme-test -t example.com --content-scan \
  --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
```

RTK subdomain nəticələrini scope ilə yenidən yoxlayır və scope xaricində olan hostları aktiv mərhələlərə ötürmür. `httpx`, `nuclei` və `feroxbuster` quraşdırılmayıbsa, uyğun mərhələ xəbərdarlıqla ötürülür. `--content-scan` üçün göstərilən wordlist mövcud deyilsə, content discovery xəbərdarlıqla keçilir. Alətlərin stdout/stderr və exit status məlumatları `logs/` qovluğunda saxlanılır.

### 2.4 Finding əlavə et

```bash
python rtk-v3.0.py finding -e acme-test \
  --title "Authentication validation issue" \
  --target "https://example.com/login" \
  --impact "Təsdiqlənmiş təsir burada qeyd olunur" \
  --fix "Tövsiyə olunan düzəliş burada qeyd olunur" \
  --poc "Təhlükəsiz, minimal reproduksiya addımları" \
  --evidence "Evidence faylının adı və ya qeydi" \
  --av N --ac L --pr N --ui N --s U --c L --i L --a N
```

CVSS metric-ləri sübutlara əsasən seçilməlidir. `--c`, `--i`, `--a` verilməzsə avtomatik `N` qəbul edilir və finding `NONE` (0.0) olur — yəni sübutsuz finding yüksək bal almır. `--impact` boş qalarsa RTK xəbərdarlıq göstərir. Finding hədəfinin host hissəsi Scope Guard-dan keçməlidir.

### 2.5 Finding-ləri idarə et

```bash
# Bütün finding-lər
python rtk-v3.0.py findings -e acme-test

# Konkret ID
python rtk-v3.0.py findings -e acme-test --id a1b2c3d4

# Status dəyiş
python rtk-v3.0.py finding-update -e acme-test \
  --id a1b2c3d4 --status "In Progress"
```

Dəstəklənən statuslar: `Open`, `In Progress`, `Fixed`, `Accepted Risk`, `False Positive`.

### 2.6 HTML hesabat

```bash
python rtk-v3.0.py report -e acme-test
```

`<engagement>/report.html` yaradılır. Hesabata severity sayları, CVSS balı, status, target və kliklənəndə açılan Impact/Fix/PoC/Evidence detalları daxildir. Severity kartları yalnız açıq finding-ləri sayır; `Fixed` və `False Positive` sətirlər solğun göstərilir və başlıqda "açıq / bağlı" bölgüsü verilir.

### 2.7 SARIF export

```bash
python rtk-v3.0.py export-sarif -e acme-test
```

`<engagement>/report.sarif` yaradılır — SARIF 2.1.0 formatında. Bu format aşağıdakı platformalarda birbaşa oxunur:

- **GitHub Security** (Code scanning alerts)
- **VS Code** (SARIF Viewer extension)
- **Azure DevOps**
- **CI/CD pipelines** (GitLab, Jenkins, GitHub Actions)

Hər finding `ruleId` (`RTK-CRITICAL`, `RTK-HIGH`, və s.), `level` (`error`/`warning`/`note`), target URI və əlavə `properties` (CVSS balı, status, fix, PoC) ilə təqdim olunur.

## 3. Interaktiv shell

Arqumentsiz başladın:

```bash
python rtk-v3.0.py
```

Nümunə:

```text
rtk > init acme-test -c "ACME Corp" -t example.com
rtk(acme-test) > osint -t example.com
rtk(acme-test) > recon -t example.com --rate-limit 3
rtk(acme-test) > findings
rtk(acme-test) > report
rtk(acme-test) > export-sarif
rtk(acme-test) > exit
```

`use <engagement>` əvvəl yaradılmış engagement-i aktiv edir. Aktiv engagement seçildikdə `-e` parametrini yazmaq məcburi deyil. `help`, `clear` və `exit` komandaları mövcuddur. Shell daxilində arqumentlər dırnaq işarələri ilə verilə bilər; Windows yolları (`C:\...`) backslash itkisi olmadan qəbul edilir.

## 4. Komandaların xülasəsi

| Komanda | Funksiya |
|---|---|
| `init` | Engagement və scope yaratmaq |
| `use` | Shell-də aktiv engagement seçmək |
| `osint` | 5 mənbədən passiv OSINT toplamaq |
| `recon` | Scope yoxlamasından sonra subfinder/httpx/nuclei işlətmək; feroxbuster opt-in |
| `finding` | Scope daxilində finding əlavə etmək və CVSS v3.1 hesablamaq |
| `findings` | Finding-ləri siyahılamaq və ID üzrə filtr etmək |
| `finding-update` | Finding statusunu dəyişmək |
| `report` | HTML hesabat yaratmaq |
| `export-sarif` | SARIF 2.1.0 formatında export (GitHub Security, VS Code) |

## 5. v3.0 dəyişiklikləri

- **Scope Guard:** hostname normallaşdırılması, subdomain sərhəd yoxlaması, IP və CIDR dəstəyi; finding target-ləri də yoxlanılır.
- **Proses təhlükəsizliyi:** xarici alətlər `shell=True` olmadan arqument siyahısı ilə başladılır; stdout/stderr, exit code və timeout loglanır.
- **Recon nəzarəti:** scope xaricindəki subdomain-lər süzülür; sorğu limiti/timeout parametrləri əlavə edilib; feroxbuster opt-in edilib.
- **CVSS v3.1:** Base Score hesablanması və standart severity aralıqları.
- **Finding workflow:** unikal ID, yaradılma vaxtı, status, evidence və status yeniləmə.
- **Hesabat:** NONE daxil olmaqla bütün severity kartları, status sütunu və escaped HTML məlumatları.
- **SARIF export:** SARIF 2.1.0 formatı — GitHub Security, VS Code və CI/CD inteqrasiyası üçün.
- **Interaktiv shell:** `use`, `help`, `clear`, `exit` və arqumentlər üçün `shlex`.
- **Mənbə xətaları:** OSINT mənbələrindən biri uğursuz olsa, digər mənbələr davam edə bilir.
- **Etibarlılıq düzəlişləri:** `--c/--i/--a` verilmədikdə `N` qəbul edilir (sübutsuz finding yüksək bal almır), hesabat kartları yalnız açıq finding-ləri sayır, boş/yanlış `score` dəyəri olan köhnə finding-lər hesabatı sındırmır.
- **Windows dəstəyi:** interaktiv shell-də `C:\...` yolları və dırnaqlı arqumentlər düzgün parse olunur.
- **Təmizlik:** istifadə olunmayan `--banner` bayrağı və əlaqəli ölü kod silinib; xarici mənbələrdən gələn mətnlər terminala yazılmazdan əvvəl idarəetmə simvollarından təmizlənir; recon dövründə `scope.json` yalnız bir dəfə oxunur.

## 6. Fayl strukturu

```text
rtk-v3.0/
├── .gitignore
├── LICENSE
├── README.md
├── rtk-v3.0.py
└── acme-test/
    ├── scope.json
    ├── osint_example.com.json
    ├── all_subs_example.com.txt
    ├── report.html
    ├── report.sarif
    └── logs/
        ├── sub_example.com.log
        ├── httpx_example.com.log
        └── nuclei_example.com.log
```

## 7. Mövcud engagement-lər və uyğunluq

RTK v3.0 əvvəlki versiyaların əsas `scope.json` quruluşundakı `name`, `client`, `scope` və `findings` sahələrini oxuya bilir. Köhnə finding-lərdə ID/status yoxdursa, onlar hesabatda görünə bilər, amma `finding-update` yalnız ID-si olan yeni finding-ləri yeniləyir. Mövcud engagement üzərində `init --force` işlətmək scope və finding məlumatlarını yenidən yaza bilər — əvvəl backup alın.

## 8. Məlum məhdudiyyətlər

- Scope Guard texniki filtrdir; təşkilatın icazə sənədini və proqram qaydalarını əvəz etmir.
- Domain scope subdomainləri əhatə edir; üçüncü tərəf xidmətləri və SaaS hostları avtomatik icazəli sayılmır.
- CVSS balı yalnız düzgün seçilmiş metric-lər qədər etibarlıdır; RTK risk qərarını özü vermir.
- Xarici alətlərin mövcudluğu, versiyası və CLI parametrləri istifadə olunan build-dən asılıdır.
- OSINT nəticələri natamam, köhnəlmiş və ya səhv ola bilər; manual təsdiq tələb olunur.
- Bu versiya tam avtomatlaşdırılmış vulnerability scanner və ya professional pentest platformasının əvəzi deyil.

## 9. Lisenziya

MIT — tam mətn üçün `LICENSE` faylına bax.