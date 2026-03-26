#include "HttpClient.hpp"
#include <iostream>

int main()
{
    Http::Client client;
    Http::Request request(Http::Method::Get, "https://github.com");

    auto response = client.Send(request);

    if(response->GetStatus() == Http::StatusCode::Ok)
    {
        auto &headers = response->GetHeaders();

        // for(const auto& [key,value] : headers)
        // {
        //     std::cout << key << ": " << value << '\n';
        // }

        std::string content;
        
        if(response->GetContentAsString(content))
        {
            std::cout << content << '\n';
        }

        std::cout << content << '\n';
    }
    else
    {
        std::cout << "Status: " << (int)response->GetStatus() << '\n';
    }

    return 0;
}
