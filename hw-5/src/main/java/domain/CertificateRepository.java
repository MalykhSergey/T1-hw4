package domain;

public interface CertificateRepository {
    Certificate findByUserName(String name);

    void save(Certificate certificate);
    void removeByName(String name);
}
