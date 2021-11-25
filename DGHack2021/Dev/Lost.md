# Lost in C++

> Corrigez le code et obtenez le flag.

```cpp
#include <iostream>
#include <string>
#include <algorithm>
#include <utility>
#include <vector>
#include <thread>
#include <condition_variable>

#define MAX_CHAR 19


class Token {
    std::array<char, MAX_CHAR> r_;

public:
    void set(int pos, char c, int shift) {
        r_.data()[pos] = c + shift;
    }

    friend std::ostream& operator<<(std::ostream& os, const Token& t) {
        os << t.r_.data();
        return os;
    }
};

template<typename T>
class Lev {

private:
    T a_, b_;
    std::shared_ptr<Token> token_;
    int pos_;

    static std::condition_variable v;
    static std::mutex m;
    static bool sig_start;
    static int shift;

public:

    Lev() = delete;
    Lev(T a, T b, std::shared_ptr<Token> token, int pos) :
        a_(a), b_(b), token_(std::move(token)), pos_(pos) {
        adjust(std::forward<T>(b));
    }

    ~Lev() = default;

    template<typename U>
    void adjust(U val) {
        if constexpr(std::is_rvalue_reference<T>::value) {
            if (token_.use_count() < shift) {
                shift = token_.use_count();
            }
        } else {
            if (token_.use_count() > shift) {
                shift = token_.use_count();
            }
        }
    }

    static void start() noexcept {
        std::unique_lock<std::mutex> lock(m);
        sig_start = true;
        v.notify_all();
    }

    constexpr int a_length() {
        return a_.length();
    }

    constexpr int b_length() {
        return b_.length();
    }

    void compute() {
        {
            std::unique_lock<std::mutex> lock(m);
            v.wait(lock, [&] { return Lev::sig_start; });
        }

        int d[a_length() + 1][b_length() + 1];

        for (int i=0; i<=a_.length(); i++) {
            d[i][0] = int(i);
        }
        for (int j=0; j<=b_.length(); j++) {
            d[0][j] = int(j);
        }

        for (int i=1; i<=a_.length(); i++) {
            for (int j=1; j<=b_.length(); j++) {
                if (a_[i-1] == b_[j-1]) {
                    d[i][j] = d[i-1][j-1];
                } else {
                    d[i][j] = std::min(d[i-1][j] + 1, std::min(d[i][j-1] + 1, d[i-1][j-1] + 1));
                }
            }
        }

        auto hc_shift = 0x34 - (MAX_CHAR-12);
        token_->set(pos_, d[a_.length()][b_.length()], shift + hc_shift);
    }
};


class Item {
private:
    std::string s_;
public:
    Item() = delete;
    explicit Item(std::string s): s_(std::move(s)) {
    }
    Item(const Item& item) {
        s_ = item.s_;
    }
    Item(Item&& item) noexcept {
        s_ = std::string(std::move(item.s_));
    }

    [[nodiscard]] int length() const {
        return s_.length();
    }

    char operator[](int i) const {
        return s_[i];
    }
};


int main() {
    std::array<std::array<Item, 2>, MAX_CHAR> v = {
            {{Item("foo"), Item("bar")},
                    {Item("développement"), Item("diversement")},
                    {Item(""), Item("")},
                    {Item("Sed ut perspiciatis, unde omnis iste natus error sit volup"), Item("")},
                    {Item("tatem accusantium dol"), Item("oremque laudantium, totam rem aperiam eaque ipsa")},
                    {Item("cybersécurité"), Item("cyber")},
                    {Item("lorem ipsum dolor sit amet, consectetur"), Item(" adipiscing elit.")},
                    {Item("Sed non risus."), Item("Suspendisse lectus tortor, dignissim sit ")},
                    {Item(" amet, adi"), Item("piscing nec, ultricies sed,")},
                    {Item("dolor. Cras elementum ultrices diam."), Item("Maecenas ligula massa, varius")},
                    {Item("a, semper congue,"), Item("euimod non, mi.")},
                    {Item("Proin porttitor, orci ne"), Item("c nonummy molestie")},
                    {Item("enim est eleifend mi, non "), Item("fermentum diam nisl sit amet")},
                    {Item("erat. Duis semper "), Item(". Duis arcu massa")},
                    {Item("scelerisque "), Item("vitae")},
                    {Item("consequat in, pretium a, enim"), Item(". Pelletesque congue. Ut in risu voluptat libero")},
                    {Item("pharetra tempor. Cras vestibulum bibendum augue. Praesent "), Item("egestas leo")},
                    {Item("in pede. Prae"), Item("sent blandit odio eu enim. Pellentesque sed dui ut augue")},
                    {Item("Aliquam convallis sollicitudin purus. Praesent aliquam, enim at fermentum mollis, "), Item("ligula massa adipiscing nisl, ac euismod")},
            }};

    std::vector<std::thread> threads{};
    threads.reserve(v.size());
    auto token = std::make_shared<Token>();
    auto pos{0};
    for (auto& [s1, s2]: v) {
        threads.emplace_back(&Lev<Item&&>::compute, std::make_unique<Lev<Item&&>>(std::move(s1), std::move(s2), token, pos++));
    }

    Lev<Item>::start();

    std::cout << token << std::endl;
    return 0;
}
```

## Description

We get a non-compiling, non-working code written in C++ that is supposed to print the flag.

We need to submit a corrected version of the code.

## Solution

Honestly I kind of cheated for this one as I did correct the code but lost a lot of features along the way.
I mostly guessed what was intended, and brute forced the 20 or so possibilities for the flag (offline, as the flag has the `DGA{...}` format).

First there were a lot of compilations errors, which had to do with wrong categories of variables (lvalues or rvalues).

To simplify things, I first removed all multithreading.

We have an array where each cell holds 2 constant strings that is being processed by the `Lev` class.

The `Lev` class first loads all strings, setting up the static variable `shift`.
Then once every cell of the array has been added, the `compute` function is called, which will fill the `token` object.

This is what will print the flag, even though there is a printing error where the address is printed and not the content.

By reading the `compute` function, I understood the functions computes the Levenshtein distance between the strings (this is actually not necessary to understand that to solve the challenge, we can consider it as a black-box computation).

The the result is saved in the token xored with the `shift` static parameter.

This is where I feel I cheated the most: instead of just understanding how the `shift` parameter is computed depending on the categories of variables, I just set `shift` to 0, computed everything and then solved the Caesar cipher to get the flag.

Here is my solution, where I highlighted my changes to make it compile, run, and print the solution:

```cpp
#include <iostream>
#include <string>
#include <algorithm>
#include <utility>
#include <vector>
#include <thread>
#include <condition_variable>

#define MAX_CHAR 19


class Token {
    std::array<char, MAX_CHAR> r_;

public:
    void set(int pos, char c, int shift) {
        r_.data()[pos] = c + shift;
    }

// Here I added a print function to show the actual data
    void print() {
        for (char c: r_)
            std::cout << c;
        std::cout << std::endl;
    }

// I guess I could have corrected this but oh well...
    friend std::ostream& operator<<(std::ostream& os, const Token& t) {
        os << t.r_.data();
        return os;
    }
};

template<typename T>
class Lev {

private:
    T a_, b_;
    std::shared_ptr<Token> token_;
    int pos_;

    // Static hardcoded shift found with Cyberchef
    static const int shift = 20;

    // Removed multithreading because who needs this?

public:

    Lev() = delete;
    Lev(T a, T b, std::shared_ptr<Token> token, int pos) :
        a_(std::move(a)), b_(std::move(b)), token_(std::move(token)), pos_(pos) {
    }

    ~Lev() = default;

    // Removed the adjust and start functions

    constexpr int a_length() {
        return a_.length();
    }

    constexpr int b_length() {
        return b_.length();
    }

    void compute() {

        int d[a_length() + 1][b_length() + 1];

        for (int i=0; i<=a_.length(); i++) {
            d[i][0] = int(i);
        }
        for (int j=0; j<=b_.length(); j++) {
            d[0][j] = int(j);
        }

        for (int i=1; i<=a_.length(); i++) {
            for (int j=1; j<=b_.length(); j++) {
                if (a_[i-1] == b_[j-1]) {
                    d[i][j] = d[i-1][j-1];
                } else {
                    d[i][j] = std::min(d[i-1][j] + 1, std::min(d[i][j-1] + 1, d[i-1][j-1] + 1));
                }
            }
        }

        auto hc_shift = 0x34 - (MAX_CHAR-12);
        token_->set(pos_, d[a_.length()][b_.length()], shift + hc_shift);
    }
};

class Item {
private:
    std::string s_;
public:
    Item() = delete;
    explicit Item(std::string s): s_(std::move(s)) {
    }
    Item(const Item& item) {
        s_ = item.s_;
    }
    Item(Item&& item) noexcept {
        s_ = std::string(std::move(item.s_));
    }

    [[nodiscard]] int length() const {
        return s_.length();
    }

    char operator[](int i) const {
        return s_[i];
    }
};


int main() {
    std::array<std::array<Item, 2>, MAX_CHAR> v = {
            {{Item("foo"), Item("bar")},
                    {Item("développement"), Item("diversement")},
                    {Item(""), Item("")},
                    {Item("Sed ut perspiciatis, unde omnis iste natus error sit volup"), Item("")},
                    {Item("tatem accusantium dol"), Item("oremque laudantium, totam rem aperiam eaque ipsa")},
                    {Item("cybersécurité"), Item("cyber")},
                    {Item("lorem ipsum dolor sit amet, consectetur"), Item(" adipiscing elit.")},
                    {Item("Sed non risus."), Item("Suspendisse lectus tortor, dignissim sit ")},
                    {Item(" amet, adi"), Item("piscing nec, ultricies sed,")},
                    {Item("dolor. Cras elementum ultrices diam."), Item("Maecenas ligula massa, varius")},
                    {Item("a, semper congue,"), Item("euimod non, mi.")},
                    {Item("Proin porttitor, orci ne"), Item("c nonummy molestie")},
                    {Item("enim est eleifend mi, non "), Item("fermentum diam nisl sit amet")},
                    {Item("erat. Duis semper "), Item(". Duis arcu massa")},
                    {Item("scelerisque "), Item("vitae")},
                    {Item("consequat in, pretium a, enim"), Item(". Pelletesque congue. Ut in risu voluptat libero")},
                    {Item("pharetra tempor. Cras vestibulum bibendum augue. Praesent "), Item("egestas leo")},
                    {Item("in pede. Prae"), Item("sent blandit odio eu enim. Pellentesque sed dui ut augue")},
                    {Item("Aliquam convallis sollicitudin purus. Praesent aliquam, enim at fermentum mollis, "), Item("ligula massa adipiscing nisl, ac euismod")},
            }};

    // Removed multithreading
    auto token = std::make_shared<Token>();
    auto pos{0};
    for (std::array<Item, 2> &s: v) {
        auto lev = new Lev<Item&&>(std::move(s[0]), std::move(s[1]), token, pos++);
        lev->compute();
    }

    token->print();
    return 0;
}
```

Flag: `DGA{gKbaX_OUVNKftp}`