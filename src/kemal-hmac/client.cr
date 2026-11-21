require "./token"

module Kemal::Hmac
  class Client
    # `client` the client name which will be sending HTTP requests to the server using HMAC auth (String)
    # `secret` the secret used to generate the HMAC token in relation to the client (String)
    # `algorithm` the algorithm used to generate the HMAC token (String) - defaults to HMAC_ALGORITHM or SHA256
    def initialize(client : String, secret : String, algorithm : String? = nil)
      @client = client
      @secret = secret
      @algorithm = Kemal::Hmac.resolve_algorithm(algorithm)

      unless KEY_VALIDATION_REGEX.match(@client.upcase)
        raise InvalidFormatError.new("client name must only contain letters, numbers, -, or _")
      end
    end

    # A public helper method to generate the HMAC headers for a given path
    # Use this method to get pre-filled headers to send with your request to the server
    # `path` the path (HTTP path) to generate the headers for (String) - e.g. "/api/path"
    # returns a Hash of the HMAC headers
    def generate_headers(path : String) : Hash(String, String)
      timestamp = Time::Format::ISO_8601_DATE_TIME.format(Time.utc)
      hmac_token = Kemal::Hmac::Token.new(@client, path.split("?").first, timestamp, @algorithm).hexdigest(@secret)

      return {
        HMAC_CLIENT_HEADER    => @client,
        HMAC_TIMESTAMP_HEADER => timestamp,
        HMAC_TOKEN_HEADER     => hmac_token,
      }
    end
  end
end
