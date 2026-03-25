#include "HttpClient.hpp"
#include <iostream>

int main()
{
    Http::Client client;
    Http::Request request(Http::Method::Get, "https://api.ipify.org");

    auto response = client.Send(request);

    if(response->GetStatus() == Http::StatusCode::Ok)
    {
        auto &headers = response->GetHeaders();

        for(const auto& [key,value] : headers)
        {
            std::cout << key << ": " << value << '\n';
        }

        //If chunked encoding is used, will not work because content length is 0
        std::string content;
        if(response->GetContentAsString(content))
        {
            std::cout << content << '\n';
        }
    }


    return 0;
}
