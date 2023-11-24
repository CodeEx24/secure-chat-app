from werkzeug.security import generate_password_hash


user_data = [
    {
        "username": "codeex24",
        "email": "user@gmail.com",
        "password": generate_password_hash("admin123"),
        "public_key": "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDURhxRKgPd5xexd8dBhNPpaT1muxkBwrE9WtQpBiUYEbvo9Bbl0yy6MCs+tt/8ZmO3iet/tF8p7wjEU0qNHdtpsq0KncmIdhyd8gM3OrWSVAaLwbD2zFjC7M0Qf8wFAOqIFgvYN42WGfWX3opNt6lavgfMA9sEGy0a8W3+Zf/yXQIDAQAB",
        "private_key": "MIICXAIBAAKBgQDURhxRKgPd5xexd8dBhNPpaT1muxkBwrE9WtQpBiUYEbvo9Bbl0yy6MCs+tt/8ZmO3iet/tF8p7wjEU0qNHdtpsq0KncmIdhyd8gM3OrWSVAaLwbD2zFjC7M0Qf8wFAOqIFgvYN42WGfWX3opNt6lavgfMA9sEGy0a8W3+Zf/yXQIDAQABAoGBAIRG+EhfnS8/XVVapZEfe4o86WVF++xL7XSlUAYMbTsVefpNeKNYt8uCTsBy5xr6lvL9gAIBXTfdW6IzoQZU769ICRvCLRcCRrrg0Jeo8NTe7CuAWQEWRIju8L16MH5VjRuHXgw1bLPkDB/u7PNJjT+CCNjclSPRsomRrKmEm3RBAkEA9qH+DHj9Jj1Z15b9GGQMhraB8ZI8TC+dN6QXGxzAXKvLKE7eC7a1rRXK4JGOxc+893hrrRpI0dFKlu6x2ae30QJBANxWDAOkC8Og0wjXx4LIFirh73graDF7DOzbnjlza1fXc31wusmMr9CDIInfiFYmNgE7LaFRHjxzFLkQC03FwM0CQE6l++C4WGnwWI0SfiVgCkqPOsLxUj8tU+JhdmjT81faBNAWzmJH4omOkIKqiC/2fhkgkp3B6wTVzAZzmc2B2XECQE8zxyHP6EKsHvAA0MDcN8u2Z6RkxhFzUBQcZeX07VMoKWWgDiTBI7nqSNoGtjVxitwqb56bUCkenQZhFA8i1MkCQGWhjx+8mwJGLe6StE5rG9CUMtiI/LXb0Rthn9PwLOJMajfkGDJsm84478gXt/7iMgTLR+g58RrK74ou/JrUQ6I=",
    },
     {
        "username": "Michael Suarez",
        "email": "user2@gmail.com",
        "password": generate_password_hash("admin123"),
        "public_key": "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCQqCgu3LZG8ARxLJt1W0masJGrOXsjWSEn84rp1PuD4D9Eds0Fg3iBaP9C9rMm/V4O6tUjpoEINV8d4qmf46b6VAz9pGGvgjXAl5EyWCRekEd2Pdwr9LQPxxWBYeUGRqsDqZ/eBVmecGpkHlPnO4MdR4diXcA2QmVCdi/DwZFUUwIDAQAB",
        "private_key": "MIICXAIBAAKBgQCQqCgu3LZG8ARxLJt1W0masJGrOXsjWSEn84rp1PuD4D9Eds0Fg3iBaP9C9rMm/V4O6tUjpoEINV8d4qmf46b6VAz9pGGvgjXAl5EyWCRekEd2Pdwr9LQPxxWBYeUGRqsDqZ/eBVmecGpkHlPnO4MdR4diXcA2QmVCdi/DwZFUUwIDAQABAoGAZ5Gdw3+Omdd6trTjUPDdD/3fLaJoAXTtAjeie6xbr528bn5IZ+wrOSw9pmoO9pls4G1N0MqDk6byxOjl3W4WvAnYQX5MPTihoMOVw/NwtF5H7l9OjAX+VYYOcYd1XEYV+Oh6L50V93/VcuGmoNa50GtH9h17s0akOlwQU6VuAOECQQDa/HkjVfQQBgTEMlN9Nz/yG2KCdEJdxROGm2RCvX4lpHFP8ZcrKhsV5lw9sxlmmpA9YdTX9gX2sOqhi8JDEOArAkEAqRt0asxcCkIwUAi/LspKWMAJWSbWrTac0NbdnbFewTgo+SvnKRGZ0mibD0oTMKwl9iS3Rh7yYXcURkhTvLYgeQJAaWbMB63/YxcChEyU0tgc9zMnHxNGPkv1MfzpLRZ3+TZFM+1cjXIex1OxYiEqQLB0bJcCE1BfXnWY+ViDkDQ3MQJBAJI2Qrn0Z8AW6l7IsURrc0y4/Vwv0H2DMqL+pC6sJRk6zXJjG0LPDQh3mVnm2iDDNy9TH4NpTngm1UjPUFdhwUECQDDB/r4HDscO8E/g966t8UXP9cA+muXkje1IJ9AjMMopyRLMBEu1bbZ5TQyl7jBEQeFTx1BtNDXZ5AC9sd9YuiU=",
    },
     {
        "username": "Glenn Ramos",
        "email": "user3@gmail.com",
        "password": generate_password_hash("User123"),
        "public_key": "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4DJ2aghkSkwbbtPOP87YZD884s4uZ+bPW8/a2Pzt3PXq8DZQqC4YfyOoFYXQyW6fUIBQF/V+cY5C0Mgc/+lEviyqXZ2oWCsfFwKsihcwITAIQrDHIDeXI5tii4Bm1i/31begKCqmBetmmUeRAeOUwmSpT+a1u6rLxRSu542CAhQIDAQAB",
        "private_key": "MIICXQIBAAKBgQC4DJ2aghkSkwbbtPOP87YZD884s4uZ+bPW8/a2Pzt3PXq8DZQqC4YfyOoFYXQyW6fUIBQF/V+cY5C0Mgc/+lEviyqXZ2oWCsfFwKsihcwITAIQrDHIDeXI5tii4Bm1i/31begKCqmBetmmUeRAeOUwmSpT+a1u6rLxRSu542CAhQIDAQABAoGAa9CAFn21oErejp++ugoDF0VKl6Wd1rIO5pF9aZ86/4vVNQojTEn55O62IDbJcaJ9eubbs/KMKrmsj9JqqtDA8z4nUDctNggBLzZlnSxwuNLQNhgVpyFshV576Fa3736QdU5h14hamT/VXW6frx6YFTtg3fIxTr38bkh1rEL2tsECQQD/6z7rXUpUVNo6NRIU8Pbkh9pl0839J8RVkdGyY5ggM+Rwny9VRo12IuF/qV0QdtofLGh0QVCt0jCnzOQGRNo1AkEAuBuKnPEHIcCrjZPM/BNi1vhPELx4iovk5mh3VwoL6C3FRdBd3VkuIsUtVtBMYk7nqSs/m262Ze7eBAPKDM5XEQJBANpdcCKER5gNjud7wSH9Oa1l/gRE5c7Mz8nz0mnUcUmI/bLbIRgySyIyQRcc/DvALf3LdpU75gtq/fkv6qEuvsECQFeEsCXe5hcDcgnBQuZpiMjMDTnVfi/ORKfK7UAxBGwAphCD9rrsU+Qve1gTeNwaykE+z+Phg099d4jNDFV+GSECQQChlvM7JLJqFbA3l2gSYiT4Yh1w6ZsjFcZnTq7aqNJ9GIl6ztL8utKXkUszSkxsxYI0uviih8bWmP6dBWw8yXww",
    },
     {
        "username": "Garen Demacia",
        "email": "user4@gmail.com",
        "password": generate_password_hash("User123"),
        "public_key": "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDWnxARcT35zN0iP8qBxztI6eLVQ3Csdb/n+q8t6YDbnQEKwgC1bqs0cE0zuMooAebycC8zW6FB+jwrc8TlC1/B+kAYxkkr9P3pishwxOPMT/Bc23WIB81ZIWT40WmfJJV7mdWrfXgTXL7MHB5ak+jczlHcRdg6gY8W+DDza1xFywIDAQAB",
        "private_key": "MIICXgIBAAKBgQDWnxARcT35zN0iP8qBxztI6eLVQ3Csdb/n+q8t6YDbnQEKwgC1bqs0cE0zuMooAebycC8zW6FB+jwrc8TlC1/B+kAYxkkr9P3pishwxOPMT/Bc23WIB81ZIWT40WmfJJV7mdWrfXgTXL7MHB5ak+jczlHcRdg6gY8W+DDza1xFywIDAQABAoGBANJFu0drjI3+cjWJDE4ENYhlZhEN5wmAwAl3KUSxPsdr1saEdo9Loz9YO7tN8/ooiu3CjewifSaYFXV5ElJZx3EHUlJYz6wAMRHTXTD1c48wNoYQzOPin9hWfynIRqfQBDKKQZAtE2Z46IimTlFa9WLa9Gy5CmLjvtX2YZxO0noZAkEA/1MdvSbqhCoyBayetPLUELbgvZzqDS9obgwOJdV4PueK49o0jx27HKUgCGtxsQS76L+Oro5o8frWacQqIHCTfwJBANcwYsS1jSZo5cuL7NggIAq7rbWXPmzKCEtOGlY5RLSFG35LtG6CEqLxBMmzXZaMqbJYfTrDF0G48xKQKfy2g7UCQFSbYU5t1+al6N+SfSDvGrDTORP8LF7kJ9HXstR8sZT+uzqX8zS9oGR0n3HK0Ojc7bvJxmk3jbUp7uUreN45D9cCQQC8ZVdDgvNl2la9Yu7jtRR4cSG/Jv/3PNYQH/v82zykkxij9OGuEmEAmOSpNkjMgrAbPU++P4k/+A2PhfnMj3o1AkEAmApKlyQ+h6PgOEuytpR5ESybGYjFdJRxjS6000JNRbRnhewC/0IcmmcShwAw6Q1jP6N81zItTf77v4niYSdtQw==",
    },
    

]
