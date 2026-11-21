require "../spec_helper"

describe "Kemal::Hmac::Client" do
  it "successfully generates a client instance" do
    client = Kemal::Hmac::Client.new("test", "test")
    client.should_not be_nil
  end

  it "successfully generates a client instance with a custom algorithm" do
    client = Kemal::Hmac::Client.new("test", "test", "SHA512")
    client.should_not be_nil
  end

  it "uses the server's default algorithm" do
    name = "test-client"
    secret = "test-secret"
    path = "/api/path"
    headers = Kemal::Hmac::Client.new(name, secret).generate_headers(path)
    handler = Kemal::Hmac::Handler.new({name => [secret]})

    handler.valid_token?(
      headers[Kemal::Hmac::HMAC_TOKEN_HEADER], secret, name, path,
      headers[Kemal::Hmac::HMAC_TIMESTAMP_HEADER],
    ).should be_true
  end

  it "rejects an unrecognized algorithm instead of defaulting to SHA256" do
    expect_raises(ArgumentError, /Unknown HMAC algorithm/) do
      Kemal::Hmac::Client.new("test-client", "test-secret", "SHA-512")
    end
    expect_raises(ArgumentError, /Unknown HMAC algorithm/) do
      Kemal::Hmac::Handler.new(hmac_algorithm: "SHA-512")
    end
  end

  it "rejects an unavailable algorithm when configuring a client or handler" do
    if OpenSSL::HMAC.digest(OpenSSL::Algorithm::MD4, "test-key", "test-message").empty?
      expect_raises(ArgumentError, /MD4.*unavailable/) do
        Kemal::Hmac::Client.new("test-client", "test-secret", "MD4")
      end
      expect_raises(ArgumentError, /MD4.*unavailable/) do
        Kemal::Hmac::Handler.new(hmac_algorithm: "MD4")
      end
    else
      Kemal::Hmac::Client.new("test-client", "test-secret", "MD4").should be_a(Kemal::Hmac::Client)
      Kemal::Hmac::Handler.new(hmac_algorithm: "MD4").should be_a(Kemal::Hmac::Handler)
    end
  end

  it "should raise an exception if the client name is invalid" do
    begin
      Kemal::Hmac::Client.new("te#!sT", "test", "SHA512")
    rescue e : Kemal::Hmac::InvalidFormatError
      e.message.should eq("client name must only contain letters, numbers, -, or _")
    end
  end

  it "should generate the proper HMAC headers" do
    client = Kemal::Hmac::Client.new("test-client", "super-secret")
    headers = client.generate_headers("/api/path")

    headers["hmac-client"].should eq("test-client")
    headers["hmac-timestamp"].should match(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/)
    headers["hmac-token"].should match(/[a-f0-9]{64}/)

    Time.parse_iso8601(headers["hmac-timestamp"]).should_not be_nil
  end

  it "should generate the proper HMAC headers with underscores provided" do
    client = Kemal::Hmac::Client.new("my_client", "my_secret")
    headers = client.generate_headers("/api/path")

    headers["hmac-client"].should eq("my_client")
    headers["hmac-timestamp"].should match(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/)
    headers["hmac-token"].should match(/[a-f0-9]{64}/)

    Time.parse_iso8601(headers["hmac-timestamp"]).should_not be_nil
  end
end
