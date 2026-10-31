// Password Similarity Detection using Bloom Filters and Bi-grams
// CSCI262 System Security - Group 33
//
// Each password is split into bi-grams, every bi-gram is hashed into a 1000-bit Bloom filter
// with 20 positions (double hashing: SHA-256 + MD5), and the per-bi-gram filters are OR-ed
// together. Candidates are compared against the dataset with Jaccard, Dice and Cosine; the
// password is rejected when the best Dice score is >= 0.70.
//
// Build: see Makefile (needs OpenSSL dev headers).

#include <algorithm>
#include <bitset>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <string>
#include <vector>

const int L = 1000;
const int K = 20;

// ============================================================
// DATASET
// ============================================================
const std::vector<std::string> DATASET = {
    "jesuslove",  "montecarlo", "taylor99",   "mellissa",   "thegreat1",  "miley123",
    "scooby-doo", "graffiti",   "december17", "purple21",   "princess15", "idontcare",
    "depression", "starbucks",  "bitchass1",  "19791979",   "football23", "kenny123",
    "papasito",   "godbless",   "baseball6",  "tanzania",   "hardcore1",  "almendra",
    "teamodiana", "portsmouth", "bestmates",  "telefoon",   "mcfly123",   "metal666",
    "mommydaddy", "matchbox20", "19951995",   "filipino",   "girlgirl",   "2hot4you",
    "iverson3",   "rubberduck", "justine1",   "typewriter", "leilani1",   "spongebob",
    "lilsaint",   "pinoyako",   "teamotanto", "pantera1",   "butterfly3", "lovesux1",
    "tweetybird", "25192519",   "fearless",   "klootzak",   "ilovechloe", "alejandro",
    "allahswt",   "scarlet1",   "morgan11",   "sexybabe1",  "cubanita",   "yesenia1",
    "believer",   "buckshot",   "gingging",   "princess99", "candice1",   "jayden06",
    "catriona",   "continuar",  "JEREMIAH",   "iluvdanny",  "tigercat",   "gorgeous1",
    "babydoll1",  "victory1",   "andrew07",   "rangers51",  "fourkids",   "bff4ever",
    "sarangheyo", "norberto",   "mexico123",  "daniel13",   "ruffryder",  "mahalqoh",
    "leapfrog",   "shankill",   "ronaldinho", "password69", "leoncito",   "20062007",
    "johndeer",   "massage1",   "alexutza",   "superman1",  "limonada",   "pinkness",
    "fernanda",   "gogators",   "aaaaaaaa",   "roserose",   "j1234567",   "babyboy7",
    "goldstar",   "cellphone1", "princessme", "brandon23",  "sidekick",   "iloveliam",
    "SUNSHINE",   "michelle01", "nickcarter", "98765432",   "chivas10",   "behappy1",
    "oscuridad",  "henderson",  "2cute4you",  "greenbean",  "pimentel",   "ronaldo17",
    "bewitched",  "keluarga",   "joseteamo",  "password25", "management", "cookie15",
    "rootbeer",   "cyclones",   "pinkflower", "hockey13",   "feyenoord",  "buddydog",
    "noviembre",  "loveyou2",   "jessica123", "kittykat1",  "sanmartin",  "jasmine2",
    "monkey123",  "MICHAEL1",   "1234abcd",   "timeless",   "0192837465", "elizabeth!",
    "jhunjhun",   "money4me",   "orquidea",   "stargate",   "sandrinha",  "ashley11",
    "summer21",   "imissyou1",  "BEAUTIFUL",  "athletics",  "cuteness",   "buckeyes",
    "webmaster",  "isabelle1",  "everlast",   "limewire",   "sexymama1",  "nikki123",
    "giselle1",   "joshua23",   "1357924680", "pinklover",  "nicole23",   "sithlord",
    "michael7",   "moonlite",   "colombia",   "mexicano",   "lilfizz1",   "babybird",
    "dictionary", "brisbane",   "bradpitt",   "scrappy1",   "football",   "ronaldo07",
    "pringles",   "123456798",  "seniors06",  "Isabella",   "password09", "jessenia",
    "sanctuary",  "lilromeo",   "fernandes",  "jessica01",  "foreverme",  "loveyou7",
    "carlos22",   "chayanne",   "ANGELINA",   "hellsing",   "tigers12",   "kennedy1",
    "dance123",   "leonhart",   "alphabet",   "mahalkoh",   "carebear1",  "chicasexy"};

// ============================================================
// HASH
// ============================================================
unsigned long long sha256Hash(const std::string &input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)input.c_str(), input.size(), hash);
    unsigned long long r = 0;
    for (int i = 0; i < 8; i++)
        r = (r << 8) | hash[i];
    return r;
}

unsigned long long md5Hash(const std::string &input) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5((unsigned char *)input.c_str(), input.size(), hash);
    unsigned long long r = 0;
    for (int i = 0; i < 8; i++)
        r = (r << 8) | hash[i];
    return r;
}

// ============================================================
// BLOOM
// ============================================================
std::bitset<1000> bigramFilter(const std::string &bg) {
    std::bitset<1000> b;
    auto f = sha256Hash(bg);
    auto g = md5Hash(bg);
    for (int i = 0; i < K; i++)
        b[(f + i * g) % L] = 1;
    return b;
}

std::vector<std::string> getBigrams(const std::string &p) {
    std::string s = " " + p + " ";
    std::vector<std::string> v;
    for (size_t i = 0; i + 1 < s.size(); i++)
        v.push_back(s.substr(i, 2));
    return v;
}

std::bitset<1000> passwordFilter(const std::string &p) {
    std::bitset<1000> c;
    for (auto &bg : getBigrams(p))
        c |= bigramFilter(bg);
    return c;
}

// ============================================================
// SIMILARITY
// ============================================================
double dice(const std::bitset<1000> &a, const std::bitset<1000> &b) {
    int g = (a & b).count();
    int d = a.count() + b.count();
    return d ? 2.0 * g / d : 0;
}

double jaccard(const std::bitset<1000> &a, const std::bitset<1000> &b) {
    int inter = (a & b).count();
    int uni = (a | b).count();

    return uni ? (double)inter / uni : 0.0;
}

double cosine(const std::bitset<1000> &a, const std::bitset<1000> &b) {
    int inter = (a & b).count();

    double denom = std::sqrt((double)a.count() * b.count());

    return denom ? inter / denom : 0.0;
}

// ============================================================
// PRINT JUSTIF
// ============================================================
void printJustif(const std::bitset<1000> &cf, const std::vector<std::bitset<1000>> &df) {
    std::cout << "\n================ JUSTIF ================\n";
    std::cout << std::left << std::setw(18) << "Password" << std::setw(12) << "Jaccard"
              << std::setw(12) << "Dice" << std::setw(12) << "Cosine" << '\n';
    double max = 0;
    int idx = 0;

    for (size_t i = 0; i < DATASET.size(); i++) {
        double j = jaccard(cf, df[i]);
        double d = dice(cf, df[i]);
        double c = cosine(cf, df[i]);

        std::cout << std::setw(18) << DATASET[i] << std::setw(12) << j << std::setw(12) << d
                  << std::setw(12) << c << '\n';
        if (d > max) {
            max = d;
            idx = i;
        }
    }

    std::cout << "\nMAX: " << DATASET[idx] << " => " << max << "\n";
    std::cout << "Decision: " << (max >= 0.70 ? "REJECT" : "ACCEPT") << "\n";
}

// ============================================================
// BLOOM DISPLAY
// ============================================================
void showBloom(int index, const std::vector<std::bitset<1000>> &df) {
    std::cout << "\nBloom Filter for #" << index + 1 << " (" << DATASET[index] << "):\n";
    std::cout << df[index] << "\n";
}

// ============================================================
// MAIN
// ============================================================
int main() {
    std::vector<std::bitset<1000>> df;
    for (auto &p : DATASET)
        df.push_back(passwordFilter(p));

    while (true) {
        std::string p;
        std::cout << "\nEnter password (8-10 chars): ";
        std::getline(std::cin, p);
        if (p == "q")
            break;

        if (p.size() < 8 || p.size() > 10) {
            std::cout << "Invalid length\n";
            continue;
        }

        auto cf = passwordFilter(p);

        printJustif(cf, df);

        double max = 0;
        for (auto &d : df)
            max = std::max(max, (double)dice(cf, d));

        std::cout << "\nFINAL: " << (max >= 0.70 ? "REJECT" : "ACCEPT") << "\n";

        // required bloom outputs
        showBloom(16, df); // 17th
        showBloom(54, df); // 55th
    }
}