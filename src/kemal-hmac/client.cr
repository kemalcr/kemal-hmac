require "./token"

module Kemal::Hmac
  class Client
    # `client` the client name which will be sending HTTP requests to the server using HMAC auth (String)
    # `secret` the secret used to generate the HMAC token in relation to the client (String)
    # `algorithm` the algorithm used to generate the HMAC token (String) - defaults to SHA256
    def initialize(client : String, secret : String, algorithm : String? = "SHA256")
      @client = client
      @secret = secret
      algo = (algorithm || ENV.fetch("HMAC_ALGORITHM", "SHA256")).upcase
      @algorithm = Kemal::Hmac.algorithm(algo)

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
      token = Token.new(@client, path.split("?").first, timestamp, @algorithm)
      build_headers(timestamp, token)
    end

    # Generates version 2 headers for the method, request target, and body being sent.
    def generate_headers(method : String, resource : String, body : String | Bytes = "") : Hash(String, String)
      timestamp = Time::Format::ISO_8601_DATE_TIME.format(Time.utc)
      target = Token.request_target(HTTP::Request.new(method, resource))
      token = Token.for_request(@client, method, target, timestamp, body, @algorithm)
      build_headers(timestamp, token)
    end

    private def build_headers(timestamp : String, token : Token) : Hash(String, String)
      {
        HMAC_CLIENT_HEADER    => @client,
        HMAC_TIMESTAMP_HEADER => timestamp,
        HMAC_TOKEN_HEADER     => token.hexdigest(@secret),
      }
    end
  end
end
