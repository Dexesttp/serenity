#include <LibCore/EventLoop.h>
#include <LibTLS/TLSv12.h>

int main()
{
    Core::EventLoop loop;
    auto host = "www.google.com";
    TLS::Options options;
    options.usable_cipher_suites = {
        TLS::CipherSuite::DHE_DSS_WITH_AES_256_GCM_SHA384
    };
    auto tls_socket = TLS::TLSv12::construct(nullptr, options);
    tls_socket->set_root_certificates(DefaultRootCACertificates::the().certificates());
    tls_socket->on_tls_ready_to_read = [&] {
        auto buffer = tls_socket->read();
        dbgln("tls read: {}", AK::StringView(buffer->data(), buffer->size()));
    };
    tls_socket->connect(host, 443);
    return loop.exec();
}
