cmake_minimum_required(VERSION 2.8)

project(crypto_project LANGUAGES C)

add_executable(differential_attack differential_attack.c toy_cipher.c)
