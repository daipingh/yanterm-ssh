#include <catch2/catch_test_macros.hpp>
#include <yanterm-ssh/detail/intrusive_list.hpp>

#include <memory>
#include <type_traits>
#include <vector>

using yanterm::ssh::detail::intrusive_list;
using yanterm::ssh::detail::intrusive_list_item;

namespace {

struct node : intrusive_list_item<node> {
    explicit node(int v) : value{v} {}
    int value;
};

template <class List>
std::vector<int> values(const List& l) {
    std::vector<int> out;
    for (const auto& n : l) out.push_back(n.value);
    return out;
}

struct by_a {};
struct by_b {};

struct multi : intrusive_list_item<multi, by_a>, intrusive_list_item<multi, by_b> {
    explicit multi(int v) : value{v} {}
    int value;
};

struct payload_base {
    virtual ~payload_base() = default;
    long pad[3] = {};
};

// The hook is neither the first base nor at offset zero.
struct late_hook : payload_base, intrusive_list_item<late_hook> {
    explicit late_hook(int v) : value{v} {}
    int value;
};

static_assert(!std::is_copy_constructible_v<intrusive_list_item<node>>);
static_assert(!std::is_move_constructible_v<intrusive_list_item<node>>);
static_assert(!std::is_copy_constructible_v<intrusive_list<node>>);
static_assert(!std::is_move_constructible_v<intrusive_list<node>>);
static_assert(!std::is_copy_assignable_v<intrusive_list<node>>);
static_assert(!std::is_move_assignable_v<intrusive_list<node>>);

}  // namespace

TEST_CASE("intrusive_list keeps insertion order and erases by node", "[detail][intrusive_list]") {
    node a{1}, b{2}, c{3};
    intrusive_list<node> l;
    REQUIRE(l.empty());
    l.push_back(a);
    l.push_back(b);
    l.push_back(c);

    REQUIRE(&l.front() == &a);
    REQUIRE(&l.back() == &c);
    REQUIRE(values(l) == std::vector<int>{1, 2, 3});

    l.erase(b);
    REQUIRE_FALSE(b.linked());
    REQUIRE(values(l) == std::vector<int>{1, 3});
    l.erase(b);  // already detached: no-op
    REQUIRE(values(l) == std::vector<int>{1, 3});

    l.pop_front();
    REQUIRE(&l.front() == &c);
    l.pop_front();
    REQUIRE(l.empty());
    l.pop_front();
    REQUIRE(l.empty());
}

TEST_CASE("intrusive_list tags let one object sit on two lists", "[detail][intrusive_list]") {
    multi x{1}, y{2}, z{3};
    intrusive_list<multi, by_a> la;
    intrusive_list<multi, by_b> lb;
    la.push_back(x);
    la.push_back(y);
    la.push_back(z);
    lb.push_back(z);
    lb.push_back(x);

    REQUIRE(values(la) == std::vector<int>{1, 2, 3});
    REQUIRE(values(lb) == std::vector<int>{3, 1});

    la.erase(x);
    REQUIRE(values(la) == std::vector<int>{2, 3});
    REQUIRE(values(lb) == std::vector<int>{3, 1});
}

TEST_CASE("intrusive_list node unlinks itself on destruction", "[detail][intrusive_list]") {
    node a{1}, c{3};
    intrusive_list<node> l;
    l.push_back(a);
    {
        node b{2};
        l.push_back(b);
        l.push_back(c);
        REQUIRE(values(l) == std::vector<int>{1, 2, 3});
    }
    REQUIRE(values(l) == std::vector<int>{1, 3});

    {
        multi m{7};
        intrusive_list<multi, by_a> la;
        intrusive_list<multi, by_b> lb;
        la.push_back(m);
        lb.push_back(m);
    }
}

TEST_CASE("intrusive_list destruction detaches remaining nodes", "[detail][intrusive_list]") {
    node a{1}, b{2};
    {
        intrusive_list<node> l;
        l.push_back(a);
        l.push_back(b);
    }
    REQUIRE_FALSE(a.linked());
    REQUIRE_FALSE(b.linked());

    intrusive_list<node> again;
    again.push_back(b);
    again.push_back(a);
    REQUIRE(values(again) == std::vector<int>{2, 1});
}

TEST_CASE("intrusive_list erase(iterator) allows deleting the current node", "[detail][intrusive_list]") {
    intrusive_list<node> l;
    for (int i = 1; i <= 5; ++i) l.push_back(*new node{i});

    std::vector<int> seen;
    for (auto it = l.begin(); it != l.end();) {
        node& n = *it;
        seen.push_back(n.value);
        if (n.value % 2 == 1) {
            it = l.erase(it);
            delete &n;
        } else {
            ++it;
        }
    }
    REQUIRE(seen == std::vector<int>{1, 2, 3, 4, 5});
    REQUIRE(values(l) == std::vector<int>{2, 4});

    for (auto it = l.begin(); it != l.end();) {
        node& n = *it;
        it = l.erase(it);
        delete &n;
    }
    REQUIRE(l.empty());
}

TEST_CASE("intrusive_list works when the hook is not the first base", "[detail][intrusive_list]") {
    auto a = std::make_unique<late_hook>(1);
    auto b = std::make_unique<late_hook>(2);
    intrusive_list<late_hook> l;
    l.push_back(*a);
    l.push_back(*b);

    REQUIRE(&l.front() == a.get());
    REQUIRE(&l.back() == b.get());
    REQUIRE(values(l) == std::vector<int>{1, 2});

    a.reset();
    REQUIRE(&l.front() == b.get());
    l.pop_front();
    REQUIRE(l.empty());
}
