//
// Created by bokket on 2020/12/9.
//

#ifndef ELF_NONCOPYABLE_H
#define ELF_NONCOPYABLE_H

class Noncopyable
{
public:
    Noncopyable(const Noncopyable &)=delete;
    Noncopyable & operator=(const Noncopyable &)=delete;

protected:
    constexpr Noncopyable()=default;
    ~Noncopyable()=default;
};

#endif //ELF_NONCOPYABLE_H
