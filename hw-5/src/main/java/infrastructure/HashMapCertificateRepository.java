package infrastructure;

import domain.Certificate;
import domain.CertificateRepository;

import java.util.HashMap;

public class HashMapCertificateRepository implements CertificateRepository {
    private final HashMap<String, Certificate> certificateHashMap = new HashMap<>();

    @Override
    public Certificate findByUserName(String name) {
        return certificateHashMap.get(name);
    }

    @Override
    public void save(Certificate certificate) {
        certificateHashMap.put(certificate.getSubjectName(), certificate);
    }

    @Override
    public void removeByName(String name) {
        certificateHashMap.remove(name);
    }
}
