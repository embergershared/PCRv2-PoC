  output public_ip { value = "${chomp(data.http.icanhazip.response_body)}" }