require "../spec_helper"

describe "Kemal::Hmac" do
  it "uses a custom handler with path matching and sends a request to an endpoint that does not require hmac auth" do
    hmac_handler = SpecAuthHandler.new(
      hmac_secrets: {"octo-client" => ["octo-secret-blue", "octo-secret-green"]},
    )
    request = HTTP::Request.new(
      "GET",
      "/health"
    )

    io, context = create_request_and_return_io_and_context(hmac_handler, request)
    response = HTTP::Client::Response.from_io(io, decompress: false)
    response.status_code.should eq 404
    context.kemal_authorized_client?.should be nil
  end

  it "uses a custom handler and correct HMAC auth and the request flows through successfully" do
    client = "valid-octo-client"
    hmac_handler = SpecAuthHandler.new(
      hmac_secrets: {client => ["octo-secret-blue", "octo-secret-green"]},
    )

    hmac_client = Kemal::Hmac::Client.new(client, "octo-secret-green", "SHA256")
    headers = hmac_client.generate_headers("/api")

    request = HTTP::Request.new(
      "GET",
      "/api",
      headers: HTTP::Headers{
        "hmac-client"    => headers["hmac-client"],
        "hmac-timestamp" => headers["hmac-timestamp"],
        "hmac-token"     => headers["hmac-token"],
      },
    )

    io, context = create_request_and_return_io_and_context(hmac_handler, request)
    response = HTTP::Client::Response.from_io(io, decompress: false)
    response.status_code.should eq 404
    context.kemal_authorized_client?.should eq(client)
  end

  it "uses a custom handler and correct HMAC auth and the request flows through successfully with query string params" do
    client = "valid-octo-client"
    hmac_handler = SpecAuthHandler.new(
      hmac_secrets: {client => ["octo-secret-blue", "octo-secret-green"]},
    )

    hmac_client = Kemal::Hmac::Client.new(client, "octo-secret-green", "SHA256")
    headers = hmac_client.generate_headers("/api")

    request = HTTP::Request.new(
      "GET",
      "/api?foo=bar&moon=star",
      headers: HTTP::Headers{
        "hmac-client"    => headers["hmac-client"],
        "hmac-timestamp" => headers["hmac-timestamp"],
        "hmac-token"     => headers["hmac-token"],
      },
    )

    io, context = create_request_and_return_io_and_context(hmac_handler, request)
    response = HTTP::Client::Response.from_io(io, decompress: false)
    response.status_code.should eq 404
    context.kemal_authorized_client?.should eq(client)
  end

  it "uses a custom handler and correct HMAC auth and the request flows through successfully with query string params incorrecty in the client" do
    client = "valid-octo-client"
    hmac_handler = SpecAuthHandler.new(
      hmac_secrets: {client => ["octo-secret-blue", "octo-secret-green"]},
    )

    hmac_client = Kemal::Hmac::Client.new(client, "octo-secret-green", "SHA256")
    headers = hmac_client.generate_headers("/api?cat=dog&moon=star&q=1")

    request = HTTP::Request.new(
      "GET",
      "/api?foo=bar&moon=star",
      headers: HTTP::Headers{
        "hmac-client"    => headers["hmac-client"],
        "hmac-timestamp" => headers["hmac-timestamp"],
        "hmac-token"     => headers["hmac-token"],
      },
    )

    io, context = create_request_and_return_io_and_context(hmac_handler, request)
    response = HTTP::Client::Response.from_io(io, decompress: false)
    response.status_code.should eq 404
    context.kemal_authorized_client?.should eq(client)
  end

  it "uses a custom handler and explicit hmac algo successfully" do
    client = "valid-octo-client"
    hmac_handler = SpecAuthHandler.new(
      hmac_secrets: {client => ["octo-secret-blue", "octo-secret-green"]},
      hmac_algorithm: "SHA256"
    )

    hmac_client = Kemal::Hmac::Client.new(client, "octo-secret-green", "SHA256")
    headers = hmac_client.generate_headers("/api")

    request = HTTP::Request.new(
      "GET",
      "/api",
      headers: HTTP::Headers{
        "hmac-client"    => headers["hmac-client"],
        "hmac-timestamp" => headers["hmac-timestamp"],
        "hmac-token"     => headers["hmac-token"],
      },
    )

    io, context = create_request_and_return_io_and_context(hmac_handler, request)
    response = HTTP::Client::Response.from_io(io, decompress: false)
    response.status_code.should eq 404
    context.kemal_authorized_client?.should eq(client)
  end

  it "uses a custom handler and explicit hmac algo for both the client and the server successfully" do
    client = "valid-octo-client"
    hmac_handler = SpecAuthHandler.new(
      hmac_secrets: {client => ["octo-secret-blue", "octo-secret-green"]},
      hmac_algorithm: "SHA512"
    )

    hmac_client = Kemal::Hmac::Client.new(client, "octo-secret-green", "SHA512")
    headers = hmac_client.generate_headers("/api")

    request = HTTP::Request.new(
      "GET",
      "/api",
      headers: HTTP::Headers{
        "hmac-client"    => headers["hmac-client"],
        "hmac-timestamp" => headers["hmac-timestamp"],
        "hmac-token"     => headers["hmac-token"],
      },
    )

    io, context = create_request_and_return_io_and_context(hmac_handler, request)
    response = HTTP::Client::Response.from_io(io, decompress: false)
    response.status_code.should eq 404
    context.kemal_authorized_client?.should eq(client)
  end

  it "uses a custom handler and explicit hmac algo and fails due to a mismatch hmac algo" do
    client = "valid-octo-client"
    hmac_handler = SpecAuthHandler.new(
      hmac_secrets: {client => ["octo-secret-blue", "octo-secret-green"]},
      hmac_algorithm: "SHA512"
    )

    hmac_client = Kemal::Hmac::Client.new(client, "octo-secret-green", "SHA256")
    headers = hmac_client.generate_headers("/api")

    request = HTTP::Request.new(
      "GET",
      "/api",
      headers: HTTP::Headers{
        "hmac-client"    => headers["hmac-client"],
        "hmac-timestamp" => headers["hmac-timestamp"],
        "hmac-token"     => headers["hmac-token"],
      },
    )

    io, context = create_request_and_return_io_and_context(hmac_handler, request)
    response = HTTP::Client::Response.from_io(io, decompress: false)
    response.status_code.should eq 401
    response.body.should contain "Unauthorized: HMAC token does not match"
    context.kemal_authorized_client?.should eq(nil)
  end

  it "uses a custom handler and correct HMAC auth and the request flows through successfully using the green secret" do
    client = "valid-octo-client"
    hmac_handler = SpecAuthHandler.new(
      hmac_secrets: {client => ["octo-secret-blue", "octo-secret-green"]},
    )

    hmac_client = Kemal::Hmac::Client.new(client, "octo-secret-green", "SHA256")
    headers = hmac_client.generate_headers("/api")

    request = HTTP::Request.new(
      "GET",
      "/api",
      headers: HTTP::Headers{
        "hmac-client"    => headers["hmac-client"],
        "hmac-timestamp" => headers["hmac-timestamp"],
        "hmac-token"     => headers["hmac-token"],
      },
    )

    io, context = create_request_and_return_io_and_context(hmac_handler, request)
    response = HTTP::Client::Response.from_io(io, decompress: false)
    response.status_code.should eq 404
    context.kemal_authorized_client?.should eq(client)
  end

  it "fails when multiple of the required HMAC headers are an empty string" do
    client = "valid-octo-client"
    hmac_handler = SpecAuthHandler.new(
      hmac_secrets: {client => ["octo-secret-blue", "octo-secret-green"]},
    )

    hmac_client = Kemal::Hmac::Client.new(client, "octo-secret-green", "SHA256")
    headers = hmac_client.generate_headers("/api")

    request = HTTP::Request.new(
      "GET",
      "/api",
      headers: HTTP::Headers{
        "hmac-client"    => headers["hmac-client"],
        "hmac-timestamp" => "",
        "hmac-token"     => "",
      },
    )

    io, context = create_request_and_return_io_and_context(hmac_handler, request)
    response = HTTP::Client::Response.from_io(io, decompress: false)
    response.status_code.should eq 401
    response.body.should contain "Unauthorized: empty required hmac headers"
    context.kemal_authorized_client?.should eq(nil)
    context.response.headers["empty-hmac-headers"].should eq "hmac-timestamp,hmac-token"
  end

  it "rejects the request when the HMAC token does not match exactly" do
    client = "valid-octo-client"
    hmac_handler = SpecAuthHandler.new(
      hmac_secrets: {client => ["octo-secret-blue", "octo-secret-green"]},
    )

    timestamp = Time::Format::ISO_8601_DATE_TIME.format(Time.utc)
    hmac_token = Kemal::Hmac::Token.new(client, "/api", timestamp).hexdigest("octoo-secret-blue")

    request = HTTP::Request.new(
      "GET",
      "/api",
      headers: HTTP::Headers{
        "hmac-client"    => client,
        "hmac-timestamp" => timestamp,
        "hmac-token"     => hmac_token,
      },
    )

    io, context = create_request_and_return_io_and_context(hmac_handler, request)
    response = HTTP::Client::Response.from_io(io, decompress: false)
    response.status_code.should eq 401
    response.body.should contain "Unauthorized: HMAC token does not match"
    context.kemal_authorized_client?.should be nil
  end

  it "rejects the request when the HMAC token does not match exactly due to a different path" do
    client = "valid-octo-client"
    hmac_handler = SpecAuthHandler.new(
      hmac_secrets: {client => ["octo-secret-blue", "octo-secret-green"]},
    )

    timestamp = Time::Format::ISO_8601_DATE_TIME.format(Time.utc)
    hmac_token = Kemal::Hmac::Token.new(client, "/api", timestamp).hexdigest("octo-secret-blue")

    request = HTTP::Request.new(
      "GET",
      "/secure",
      headers: HTTP::Headers{
        "hmac-client"    => client,
        "hmac-timestamp" => timestamp,
        "hmac-token"     => hmac_token,
      },
    )

    io, context = create_request_and_return_io_and_context(hmac_handler, request)
    response = HTTP::Client::Response.from_io(io, decompress: false)
    response.status_code.should eq 401
    response.body.should contain "Unauthorized: HMAC token does not match"
    context.kemal_authorized_client?.should be nil
  end

  it "rejects the request when the HMAC token does not match exactly since the timestamp is different" do
    client = "valid-octo-client"
    hmac_handler = SpecAuthHandler.new(
      hmac_secrets: {client => ["octo-secret-blue", "octo-secret-green"]},
    )

    timestamp = Time::Format::ISO_8601_DATE_TIME.format(Time.utc + 1.second)
    hmac_token = Kemal::Hmac::Token.new(client, "/api", timestamp).hexdigest("octoo-secret-blue")

    request = HTTP::Request.new(
      "GET",
      "/api",
      headers: HTTP::Headers{
        "hmac-client"    => client,
        "hmac-timestamp" => timestamp,
        "hmac-token"     => hmac_token,
      },
    )

    io, context = create_request_and_return_io_and_context(hmac_handler, request)
    response = HTTP::Client::Response.from_io(io, decompress: false)
    response.status_code.should eq 401
    response.body.should contain "Unauthorized: HMAC token does not match"
    context.kemal_authorized_client?.should be nil
  end

  it "uses a custom handler and fails due to no matching client secrets" do
    hmac_handler = SpecAuthHandler.new(
      hmac_secrets: {} of String => Array(String),
    )
    request = HTTP::Request.new(
      "GET",
      "/api",
      headers: HTTP::Headers{
        "hmac-client"    => "octo-client-with-no-secrets",
        "hmac-timestamp" => Time::Format::ISO_8601_DATE_TIME.format(Time.utc),
        "hmac-token"     => "octo-token",
      },
    )

    io, context = create_request_and_return_io_and_context(hmac_handler, request)
    response = HTTP::Client::Response.from_io(io, decompress: false)
    response.status_code.should eq 401
    response.body.should contain "Unauthorized: no secrets found for client: octo-client-with-no-secrets"
    context.kemal_authorized_client?.should be nil
  end

  it "uses a custom handler and fails due to a failed secret regex match" do
    hmac_handler = SpecAuthHandler.new(
      hmac_secrets: {} of String => Array(String),
      enable_env_lookup: true
    )
    request = HTTP::Request.new(
      "GET",
      "/api",
      headers: HTTP::Headers{
        "hmac-client"    => "octo-client-&-bad-secret",
        "hmac-timestamp" => Time::Format::ISO_8601_DATE_TIME.format(Time.utc),
        "hmac-token"     => "octo-token",
      },
    )

    io, context = create_request_and_return_io_and_context(hmac_handler, request)
    response = HTTP::Client::Response.from_io(io, decompress: false)
    response.status_code.should eq 401
    response.body.should contain "Unauthorized: client name must only contain letters, numbers, -, or _"
    context.kemal_authorized_client?.should be nil
  end

  it "calls the hmac_auth helper method without errors" do
    hmac_auth[0].to_s.should contain "Kemal::Hmac::Handler"
  end

  it "returns 401 when a header is provided but it is not for hmac auth" do
    hmac_handler = Kemal::Hmac::Handler.new
    request = HTTP::Request.new(
      "GET",
      "/",
      headers: HTTP::Headers{"x-no-hmac-auth-whoops" => "foobar"},
    )
    io, context = create_request_and_return_io_and_context(hmac_handler, request)
    response = HTTP::Client::Response.from_io(io, decompress: false)
    response.status_code.should eq 401
    response.headers["missing-hmac-headers"].should eq "hmac-client,hmac-timestamp,hmac-token"
    response.body.should contain "Unauthorized: missing required hmac headers"
    context.kemal_authorized_client?.should eq(nil)
  end

  it "returns 401 when no headers are provided at all" do
    hmac_handler = Kemal::Hmac::Handler.new
    request = HTTP::Request.new(
      "GET",
      "/"
    )
    io, context = create_request_and_return_io_and_context(hmac_handler, request)
    response = HTTP::Client::Response.from_io(io, decompress: false)
    response.status_code.should eq 401
    response.headers["missing-hmac-headers"].should eq "hmac-client,hmac-timestamp,hmac-token"
    response.body.should contain "Unauthorized: missing required hmac headers"
    context.kemal_authorized_client?.should eq(nil)
  end

  it "returns 401 when only the client hmac header is provided" do
    hmac_handler = Kemal::Hmac::Handler.new
    request = HTTP::Request.new(
      "GET",
      "/",
      headers: HTTP::Headers{"hmac-client" => "octo-client"},
    )
    io, context = create_request_and_return_io_and_context(hmac_handler, request)
    response = HTTP::Client::Response.from_io(io, decompress: false)
    response.status_code.should eq 401
    response.headers["missing-hmac-headers"].should eq "hmac-timestamp,hmac-token"
    response.body.should contain "Unauthorized: missing required hmac headers"
    context.kemal_authorized_client?.should eq(nil)
  end

  it "returns 401 when the timestamp is not a valid ISO8601 string" do
    hmac_handler = Kemal::Hmac::Handler.new
    request = HTTP::Request.new(
      "GET",
      "/",
      headers: HTTP::Headers{
        "hmac-client"    => "octo-client",
        "hmac-timestamp" => Time.utc.to_s,
        "hmac-token"     => "octo-token",
      },
    )
    io, context = create_request_and_return_io_and_context(hmac_handler, request)
    response = HTTP::Client::Response.from_io(io, decompress: false)
    response.status_code.should eq 401
    response.body.should contain "Unauthorized: Timestamp isn't a valid ISO8601 string"
    context.kemal_authorized_client?.should eq(nil)
  end

  it "returns 401 when the timestamp is too far in the future" do
    hmac_handler = Kemal::Hmac::Handler.new
    request = HTTP::Request.new(
      "GET",
      "/",
      headers: HTTP::Headers{
        "hmac-client"    => "octo-client",
        "hmac-timestamp" => Time::Format::ISO_8601_DATE_TIME.format(Time.utc + 100.seconds),
        "hmac-token"     => "octo-token",
      },
    )
    io, context = create_request_and_return_io_and_context(hmac_handler, request)
    response = HTTP::Client::Response.from_io(io, decompress: false)
    response.status_code.should eq 401
    response.body.should contain "Unauthorized: Timestamp is too old or in the future (ensure it's in UTC)"
    context.kemal_authorized_client?.should eq(nil)
  end

  it "returns 401 when the timestamp is too far in the past" do
    hmac_handler = Kemal::Hmac::Handler.new
    request = HTTP::Request.new(
      "GET",
      "/",
      headers: HTTP::Headers{
        "hmac-client"    => "octo-client",
        "hmac-timestamp" => Time::Format::ISO_8601_DATE_TIME.format(Time.utc - 100.seconds),
        "hmac-token"     => "octo-token",
      },
    )
    io, context = create_request_and_return_io_and_context(hmac_handler, request)
    response = HTTP::Client::Response.from_io(io, decompress: false)
    response.status_code.should eq 401
    response.body.should contain "Unauthorized: Timestamp is too old or in the future (ensure it's in UTC)"
    context.kemal_authorized_client?.should eq(nil)
  end

  it "successfully flows through and passes when fetching secrets from the ENV" do
    client = "Octo1-Client_prod"
    secret = "super-secret"
    hmac_handler = Kemal::Hmac::Handler.new(enable_env_lookup: true)
    hmac_client = Kemal::Hmac::Client.new(client, secret, "SHA256")
    headers = hmac_client.generate_headers("/api")

    ENV["#{client.upcase}_HMAC_SECRET_BLUE"] = "unset"
    ENV["#{client.upcase}_HMAC_SECRET_GREEN"] = secret

    request = HTTP::Request.new(
      "GET",
      "/api",
      headers: HTTP::Headers{
        "hmac-client"    => headers["hmac-client"],
        "hmac-timestamp" => headers["hmac-timestamp"],
        "hmac-token"     => headers["hmac-token"],
      },
    )

    io, context = create_request_and_return_io_and_context(hmac_handler, request)
    response = HTTP::Client::Response.from_io(io, decompress: false)
    response.status_code.should eq 404
    context.kemal_authorized_client?.should eq(client)
  end

  it "fails to flow through when fetching secrets from the env since it is disabled by default" do
    client = "Octo1-Client_prod"
    secret = "super-secret"
    hmac_handler = Kemal::Hmac::Handler.new
    hmac_client = Kemal::Hmac::Client.new(client, secret, "SHA256")
    headers = hmac_client.generate_headers("/api")

    ENV["#{client.upcase}_HMAC_SECRET_BLUE"] = "unset"
    ENV["#{client.upcase}_HMAC_SECRET_GREEN"] = secret

    request = HTTP::Request.new(
      "GET",
      "/api",
      headers: HTTP::Headers{
        "hmac-client"    => headers["hmac-client"],
        "hmac-timestamp" => headers["hmac-timestamp"],
        "hmac-token"     => headers["hmac-token"],
      },
    )

    io, context = create_request_and_return_io_and_context(hmac_handler, request)
    response = HTTP::Client::Response.from_io(io, decompress: false)
    response.status_code.should eq 401
    response.body.should contain "Unauthorized: no secrets found for client: Octo1-Client_prod"
    context.kemal_authorized_client?.should eq(nil)
  end
end

describe "Version 2 request signatures" do
  it "authenticates a signed binary body and leaves it available to the route" do
    name = "test-client"
    secret = "test-secret"
    target = "/api/Report?filter=Jane%20Doe&order=desc"
    body = Bytes[0, 128, 255]
    client = Kemal::Hmac::Client.new(name, secret)
    headers = HTTP::Headers.new
    client.generate_headers("POST", target, body).each { |key, value| headers[key] = value }
    request = HTTP::Request.new("POST", target, headers, body)
    request.path.should eq("/api/Report")
    handler = hmac_auth({name => [secret]}, signature_version: 2, max_signed_body_bytes: body.size).last[1]
    handler.next = ->(context : HTTP::Server::Context) do
      context.request.body.not_nil!.read_bytes(UInt8).should eq(0)
      context.request.body.not_nil!.read_bytes(UInt8).should eq(128)
      context.request.body.not_nil!.read_bytes(UInt8).should eq(255)
      context.response.print "signed body received"
    end

    io, context = create_request_and_return_io_and_context(handler, request)

    context.response.status_code.should eq(200)
    context.kemal_authorized_client?.should eq(name)
    io.gets_to_end.should contain("signed body received")
  end

  it "binds each request field to the signature" do
    name = "test-client"
    secret = "test-secret"
    timestamp = "2026-01-01T00:00:00Z"
    target = "/api/Report?format=json"
    body = "report content"
    algorithm = OpenSSL::Algorithm::SHA256
    signature = Kemal::Hmac::Token.for_request(name, "POST", target, timestamp, body, algorithm).hexdigest(secret)
    signature.should eq("eaa4ed45f37eee3051a26f6b2cbd082bb3500ba75950c2fa3c3e19a96fe1ec0c")

    {
      {"PUT", target, body},
      {"POST", "/api/report?format=json", body},
      {"POST", "/api/Report?format=text", body},
      {"POST", target, "different content"},
    }.each do |method, path, content|
      Kemal::Hmac::Token.for_request(name, method, path, timestamp, content, algorithm).hexdigest(secret).should_not eq(signature)
    end
  end

  it "authenticates an empty body and normalizes an empty query delimiter" do
    name = "test-client"
    secret = "test-secret"
    target = "/api/report?"
    client = Kemal::Hmac::Client.new(name, secret)
    headers = HTTP::Headers.new
    client.generate_headers("GET", target).each { |key, value| headers[key] = value }
    request = HTTP::Request.new("GET", target, headers)
    request.path.should eq("/api/report")
    handler = Kemal::Hmac::Handler.new({name => [secret]}, signature_version: 2)
    handler.next = ->(context : HTTP::Server::Context) { context.response.print "signed request received" }

    io, context = create_request_and_return_io_and_context(handler, request)

    context.response.status_code.should eq(200)
    io.gets_to_end.should contain("signed request received")
  end

  it "returns 413 when a request exceeds the configured body limit" do
    name = "test-client"
    secret = "test-secret"
    target = "/api/report"
    body = "report content"
    client = Kemal::Hmac::Client.new(name, secret)
    headers = HTTP::Headers.new
    client.generate_headers("POST", target, body).each { |key, value| headers[key] = value }
    inputs = {IO::Memory.new(body), HTTP::FixedLengthContent.new(IO::Memory.new(body), body.bytesize)}
    inputs.each do |input|
      request = HTTP::Request.new("POST", target, headers)
      request.body = input
      handler = Kemal::Hmac::Handler.new({name => [secret]}, signature_version: 2, max_signed_body_bytes: 2)

      _, context = create_request_and_return_io_and_context(handler, request)

      context.response.status_code.should eq(413)
      context.response.headers["Connection"].should eq("close")
      context.kemal_authorized_client?.should be_nil
    end
  end

  it "returns 400 for a prematurely ended fixed-length body" do
    name = "test-client"
    secret = "test-secret"
    target = "/api/report"
    body = "report content"
    client = Kemal::Hmac::Client.new(name, secret)
    headers = HTTP::Headers.new
    client.generate_headers("POST", target, body).each { |key, value| headers[key] = value }
    request = HTTP::Request.new("POST", target, headers)
    request.body = HTTP::FixedLengthContent.new(IO::Memory.new("report"), body.bytesize)
    handler = Kemal::Hmac::Handler.new({name => [secret]}, signature_version: 2)

    _, context = create_request_and_return_io_and_context(handler, request)

    context.response.status_code.should eq(400)
    context.response.headers["Connection"].should eq("close")
    context.kemal_authorized_client?.should be_nil
  end

  it "returns 400 when the signed body cannot be read" do
    name = "test-client"
    secret = "test-secret"
    target = "/api/report"
    body = "report content"
    client = Kemal::Hmac::Client.new(name, secret)
    headers = HTTP::Headers.new
    client.generate_headers("POST", target, body).each { |key, value| headers[key] = value }
    request = HTTP::Request.new("POST", target, headers)
    input = IO::Memory.new(body)
    request.body = input
    input.close
    handler = Kemal::Hmac::Handler.new({name => [secret]}, signature_version: 2)

    _, context = create_request_and_return_io_and_context(handler, request)

    context.response.status_code.should eq(400)
    context.response.headers["Connection"].should eq("close")
  end

  it "rejects invalid signature settings at initialization" do
    expect_raises(ArgumentError, /signature_version/) do
      Kemal::Hmac::Handler.new(signature_version: 3)
    end
    expect_raises(ArgumentError, /max_signed_body_bytes/) do
      Kemal::Hmac::Handler.new(signature_version: 2, max_signed_body_bytes: -1)
    end
  end
end
