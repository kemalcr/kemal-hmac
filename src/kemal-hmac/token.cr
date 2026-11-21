require "digest/sha256"
require "http/request"
require "openssl"
require "openssl/hmac"

module Kemal::Hmac
  class Token
    # `subject` the subject of the token (String)
    # `resource` the resource of the token (String)
    # `timestamp` the timestamp of the token (String)
    def initialize(subject : String, resource : String, timestamp : String, algorithm : OpenSSL::Algorithm? = nil)
      @message = [subject.downcase, resource.downcase, timestamp].join(HMAC_KEY_DELIMITER)
      @algorithm = algorithm || ALGORITHM
    end

    # Use the same parsed path and query that the application sees.
    def self.request_target(request : HTTP::Request) : String
      path = request.path
      query = request.query
      query && !query.empty? ? "#{path}?#{query}" : path
    end

    # Version 2 binds the method, parsed request target, and body bytes.
    def self.for_request(subject : String, method : String, resource : String, timestamp : String, body : String | Bytes, algorithm : OpenSSL::Algorithm? = nil) : self
      body_digest = Digest::SHA256.hexdigest(body)
      message = String.build do |io|
        io << "kemal-hmac-v2\n"
        {subject, method, resource, timestamp, body_digest}.each do |field|
          io << field.bytesize << ':' << field
        end
      end
      new(message, algorithm || ALGORITHM)
    end

    private def initialize(@message : String, @algorithm : OpenSSL::Algorithm)
    end

    # Build an HMAC token with the given secret
    # `secret` the secret used to build token
    # returns HMAC token (hexdigest)
    def hexdigest(secret : String) : String
      OpenSSL::HMAC.hexdigest(@algorithm, secret, @message)
    end
  end
end
