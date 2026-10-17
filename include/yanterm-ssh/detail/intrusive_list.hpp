#pragma once

#include <yanterm-ssh/detail/config.hpp>

#include <cstddef>
#include <iterator>
#include <type_traits>

namespace yanterm::ssh::detail {

template <class T, class Tag = void>
class intrusive_list;

// Base-class hook, after corral's IntrusiveListItem. T derives from
// intrusive_list_item<T, Tag> once per list it can be linked into; distinct
// Tags let one object sit on several lists. A node unlinks itself on
// destruction. Detached nodes have null links.
template <class T, class Tag = void>
class intrusive_list_item {
public:
    intrusive_list_item() noexcept = default;
    intrusive_list_item(const intrusive_list_item&) = delete;
    intrusive_list_item& operator=(const intrusive_list_item&) = delete;
    intrusive_list_item(intrusive_list_item&&) = delete;
    intrusive_list_item& operator=(intrusive_list_item&&) = delete;

    ~intrusive_list_item() {
        static_assert(std::is_base_of_v<intrusive_list_item, T>,
                      "T must derive from intrusive_list_item<T, Tag>");
        unlink();
    }

    [[nodiscard]] bool linked() const noexcept { return next_ != nullptr; }

    void unlink() noexcept {
        if (next_ == nullptr) return;
        prev_->next_ = next_;
        next_->prev_ = prev_;
        prev_ = nullptr;
        next_ = nullptr;
    }

private:
    friend class intrusive_list<T, Tag>;

    intrusive_list_item* prev_ = nullptr;
    intrusive_list_item* next_ = nullptr;
};

// Circular doubly-linked list with an embedded sentinel. Nodes are not owned;
// destroying the list detaches every node.
template <class T, class Tag>
class intrusive_list {
    using item = intrusive_list_item<T, Tag>;

    template <bool Const>
    class basic_iterator {
        using item_ptr = std::conditional_t<Const, const item*, item*>;

    public:
        using iterator_category = std::bidirectional_iterator_tag;
        using value_type = T;
        using difference_type = std::ptrdiff_t;
        using pointer = std::conditional_t<Const, const T*, T*>;
        using reference = std::conditional_t<Const, const T&, T&>;

        basic_iterator() noexcept = default;
        template <bool C = Const, class = std::enable_if_t<C>>
        basic_iterator(const basic_iterator<false>& o) noexcept : p_{o.p_} {}

        reference operator*() const noexcept { return *static_cast<pointer>(p_); }
        pointer operator->() const noexcept { return static_cast<pointer>(p_); }

        basic_iterator& operator++() noexcept { p_ = p_->next_; return *this; }
        basic_iterator operator++(int) noexcept { auto t = *this; p_ = p_->next_; return t; }
        basic_iterator& operator--() noexcept { p_ = p_->prev_; return *this; }
        basic_iterator operator--(int) noexcept { auto t = *this; p_ = p_->prev_; return t; }

        friend bool operator==(const basic_iterator& a, const basic_iterator& b) noexcept {
            return a.p_ == b.p_;
        }

    private:
        friend class intrusive_list;
        friend class basic_iterator<!Const>;
        explicit basic_iterator(item_ptr p) noexcept : p_{p} {}
        item_ptr p_ = nullptr;
    };

public:
    using iterator = basic_iterator<false>;
    using const_iterator = basic_iterator<true>;

    intrusive_list() noexcept {
        head_.prev_ = &head_;
        head_.next_ = &head_;
    }
    intrusive_list(const intrusive_list&) = delete;
    intrusive_list& operator=(const intrusive_list&) = delete;
    intrusive_list(intrusive_list&&) = delete;
    intrusive_list& operator=(intrusive_list&&) = delete;
    ~intrusive_list() { clear(); }

    [[nodiscard]] bool empty() const noexcept { return head_.next_ == &head_; }

    [[nodiscard]] T& front() noexcept { return *begin(); }
    [[nodiscard]] const T& front() const noexcept { return *begin(); }
    [[nodiscard]] T& back() noexcept { return *iterator{head_.prev_}; }
    [[nodiscard]] const T& back() const noexcept { return *const_iterator{head_.prev_}; }

    iterator begin() noexcept { return iterator{head_.next_}; }
    iterator end() noexcept { return iterator{&head_}; }
    const_iterator begin() const noexcept { return const_iterator{head_.next_}; }
    const_iterator end() const noexcept { return const_iterator{&head_}; }

    // Precondition: node is not linked into any list with this Tag.
    void push_back(T& node) noexcept {
        item& n = node;
        n.prev_ = head_.prev_;
        n.next_ = &head_;
        head_.prev_->next_ = &n;
        head_.prev_ = &n;
    }

    void pop_front() noexcept {
        if (!empty()) head_.next_->unlink();
    }

    // Unlinks node; no-op if node is already detached.
    void erase(T& node) noexcept { static_cast<item&>(node).unlink(); }

    // Unlinks *pos and returns the following position, so the caller may
    // destroy the erased node while iterating.
    iterator erase(iterator pos) noexcept {
        item* next = pos.p_->next_;
        pos.p_->unlink();
        return iterator{next};
    }

    void clear() noexcept {
        while (!empty()) head_.next_->unlink();
    }

private:
    item head_;
};

}  // namespace yanterm::ssh::detail
