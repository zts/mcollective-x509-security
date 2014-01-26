require 'base64'
require 'openssl'
require 'rbconfig'

module MCollective
  module Security

    # client.cfg:
    #
    #   securityprovider = x509
    #   plugin.x509.serializer = yaml
    #   plugin.x509.cacert = /home/john/.mc/cacert.pem
    #   plugin.x509.client_key = /home/john/.mc/john-key.pem
    #   plugin.x509.client_cert = /home/john/.mc/john-cert.pem
    #
    # server.cfg:
    #
    #   securityprovider = x509
    #   plugin.x509.serializer = yaml
    #   plugin.x509.cacert = /etc/mcollective/server_cacert.pem
    #   plugin.x509.server_key = /etc/mcollective/server_key.pem
    #   plugin.x509.server_cert = /etc/mcollective/server_cert.pem

    class X509 < Base
      def initialize
        super
        @serializer = @config.pluginconf["x509.serializer"] || "marshal"
        if @serializer == 'yaml'
          require 'yaml'
          if RbConfig::CONFIG['MAJOR'] == '2'
            require 'syck'
          end
          YAML::ENGINE.yamler = 'syck' if defined?(YAML::ENGINE)
        end
      end

      def valid_callerid?(callerid)
        begin
          dn = OpenSSL::X509::Name.parse(callerid)
          true
        rescue TypeError
          false
        rescue OpenSSL::X509::NameError
          false
        end
      end

      def decodemsg(msg)
        body = deserialize(msg.payload)

        should_process_msg?(msg, body[:requestid])

        if validrequest?(body)
          body[:body] = deserialize(body[:body])
          return body
        else
          nil
        end
      end

      # Encodes a reply
      def encodereply(sender, msg, requestid, requestcallerid=nil)
        serialized  = serialize(msg)
        sig, cert = sign(serialized)

        req = create_reply(requestid, sender, serialized)
        req[:sig] = sig
        req[:cert] = cert

        serialize(req)
      end

      # Encodes a request msg
      def encoderequest(sender, msg, requestid, filter, target_agent, target_collective, ttl=60)
        req = create_request(requestid, filter, "", @initiated_by, target_agent, target_collective, ttl)

        serialized = serialize(msg)
        sig, cert = sign(serialized)

        req[:sig] = sig
        req[:cert] = cert
        req[:body] = serialized

        serialize(req)
      end

      # Checks the SSL signature in the request body
      def validrequest?(req)
        message = req[:body]

        Log.debug("Validating request from #{req[:callerid]}")

        cert = verify(req[:cert], req[:sig], message.to_s)

        # if signature doesn't check out, fail
        if cert == false
          @stats.unvalidated
          raise(SecurityValidationFailed,
            "Received an invalid signature in message, claimed #{req[:callerid]}")
        else

          # if no callerid, assume valid (responses are like this)
          if req[:callerid].nil?
            @stats.validated
            return true
          end

          # if a callerid is claimed, check it against the certificate
          if cert.subject.to_s == req[:callerid]
            @stats.validated
            return true
          else
            @stats.unvalidated
            raise(SecurityValidationFailed,
              "Received incorrect callerid, claimed #{req[:callerid]}, was #{cert.subject}")
          end
        end
      end

      # sets the caller id to the DN of the certificate
      def callerid
        cert.subject.to_s
      end

      private
      # Serializes a message using the configured encoder
      def serialize(msg)
        Log.debug("Serializing using #{@serializer}")

        case @serializer
        when "yaml"
          return YAML.dump(msg)
        else
          return Marshal.dump(msg)
        end
      end

      # De-Serializes a message using the configured encoder
      def deserialize(msg)
        Log.debug("De-Serializing using #{@serializer}")

        case @serializer
        when "yaml"
          return YAML.load(msg)
        else
          return Marshal.load(msg)
        end
      end

      # Figures out the CA certificate either from MCOLLECTIVE_X509_CACERT or the
      # plugin.x509.ca_cert config option
      def cacert
        return ENV["MCOLLECTIVE_X509_CACERT"] if ENV.include?("MCOLLECTIVE_X509_CACERT")

        unless @config.pluginconf.include?("x509.cacert")
          raise("No plugin.x509.cacert configuration option specified")
        end

        cert_text = File.read(@config.pluginconf["x509.cacert"])
        cert = OpenSSL::X509::Certificate.new(cert_text)

        return cert
      end

      # Figures out the client private key either from MCOLLECTIVE_X509_KEY or the
      # plugin.x509.client_key config option
      def client_key_path
        return ENV["MCOLLECTIVE_X509_KEY"] if ENV.include?("MCOLLECTIVE_X509_KEY")

        unless @config.pluginconf.include?("x509.client_key")
          raise("No plugin.x509.client_key configuration option specified")
        end

        return @config.pluginconf["x509.client_key"]
      end

      # Figures out the client public key either from MCOLLECTIVE_CLIENT_CERT or the
      # plugin.x509.client_cert config option
      def client_cert_path
        return ENV["MCOLLECTIVE_X509_cert"] if ENV.include?("MCOLLECTIVE_X509_CERT")

        unless @config.pluginconf.include?("x509.client_cert")
          raise("No plugin.x509.client_cert configuration option specified")
        end

        return @config.pluginconf["x509.client_cert"]
      end

      # Figures out the server private key either from MCOLLECTIVE_X509_KEY or the
      # plugin.x509.server_key config option
      def server_key_path
        unless @config.pluginconf.include?("x509.server_key")
          raise("No plugin.x509.server_key configuration option specified")
        end

        return @config.pluginconf["x509.server_key"]
      end

      # Figures out the server public key either from MCOLLECTIVE_SERVER_CERT or the
      # plugin.x509.server_cert config option
      def server_cert_path
        unless @config.pluginconf.include?("x509.server_cert")
          raise("No plugin.x509.server_cert configuration option specified")
        end

        return @config.pluginconf["x509.server_cert"]
      end

      def key
        if @initiated_by == :node
          key_path = server_key_path
        else
          key_path = client_key_path
        end

        key_text = File.read(key_path)
        key = OpenSSL::PKey::RSA::new(key_text)

        return key
      end

      def cert
        if @initiated_by == :node
          cert_path = server_cert_path
        else
          cert_path = client_cert_path
        end

        cert_text = File.read(cert_path)
        cert = OpenSSL::X509::Certificate.new(cert_text)

        return cert
      end

      # Sign message with the appropriate private key
      def sign(message)
        # remove trailing whitespace - will be stripped by YAML,
        # breaking the signature verification.
        message.gsub!(/\s+$/, '')
        sig = Base64.encode64(key.sign(OpenSSL::Digest::SHA1.new, message))
        return sig, cert.to_s
      end

      # Verify the signature on the message with the given
      # certificate, and check the certificate is signed by the CA
      # certificate.
      def verify(cert_text, signature, message)
        cert = OpenSSL::X509::Certificate.new(cert_text)
        pubkey = cert.public_key
        ret = pubkey.verify(OpenSSL::Digest::SHA1.new, Base64.decode64(signature), message)
        return false unless ret
        ret = cert.verify(cacert.public_key)
        return ret ? cert : false
      end
    end
  end
end
