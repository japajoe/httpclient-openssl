# httpclient

Binaries for Windows and Linux can be found in `runtimes` folder. Copy the files to the same directory as the executable so it can be found when the program runs.

# example
```cpp
#include "HttpClient.hpp"
#include <iostream>

int main()
{
    Http::Client client;
    Http::Request request(Http::Method::Get, "https://www.google.com");

    auto response = client.Send(request);

    if(response->GetStatus() == Http::StatusCode::Ok)
    {
        auto &headers = response->GetHeaders();

        for(const auto& [key,value] : headers)
        {
            std::cout << key << ": " << value << '\n';
        }

        std::string content;
        
        if(response->GetContentAsString(content))
        {
            std::cout << content << '\n';
        }
    }
    else
    {
        std::cout << "Status: " << (int)response->GetStatus() << '\n';
    }

    return 0;
}
```

# TLDR
Just use curl.