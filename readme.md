# Домашнее задание №5 IT-лагеря Т1

## Описание
Реализация веб-сервиса авторизации на основе библиотеки 
безопасного общения, реализованной в https://github.com/MalykhSergey/T1-hw5/tree/master.

## Запуск
Для запуска системного теста:
```shell
docker compose up test
```

Для запуска сервиса (при его сборке прогоняются тесты библиотеки):

```shell
docker compose up cert-auth
```

Сервис требует библиотеки (https://github.com/MalykhSergey/T1-hw5/tree/master). В docker это учтено.
При желании запустить локально, необходимо выполнить *mvn install* у библиотеки, после чего
запустить СУБД (*docker compose up postgres -d* или *docker compose up postgres_test -d*). Затем приложение
может быть запущено командой *mvn spring-boot:run*.

## Описание реализации

В качестве основы сервиса авторизации взят сервис реализованный в ходе задания №4 https://github.com/MalykhSergey/T1-hw5/tree/master.

У сервиса доступен UI посредством swagger: http://127.0.0.1:8080/swagger-ui/index.html. 
Там можно вручную зарегистрироваться (и лишь при очень большом желании выполнить что-то ещё).
Публичный ключ для теста регистрации:
```
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkHtKRGWQd5Goa9RldxIVZPBHMx8AW828n8+zmzex3F2SRWqItRm4L7AisooIOKIkhXEzLokDEmo6NfMhKydHBJl9KEczfQnKq+8v2e1109BwigDYnvMz5dooQe8BoLu7moFXC25H9or1YssnBVSUdh5masrklksOLkKolDtn1XqKUDlk00iu4dJJzWZUJAoRLtK+phtD8A9aUT3JamFCky41oRQThoJLzwVrW29q6GQQDlyuy2GyCgv9nERYyn2suGvnXE+p/pRQjNBehKnBVLojv2udMAovvWx4Z9cJpEg4tytwuJ5V3D9bESOwDraFHGetybGOVQybi5CVsDaRYQIDAQAB
```
Алгоритм *RSA*.

После регистрации участник обмена уходит из центра сертификации с двумя сертификатами.
Эти сертификаты содержат всё необходимое для безопасного общения. Сертификат пользователя, который он предъявляет
вместе с сообщением. Сертификат доверенного центра, который используется для проверки чужих сертификатов. Также пользователь
может дополнительно узнавать у центра сертификации о действительности других сертификатов.

Более подробно о формате общения, и почему он безопасен описано здесь: https://github.com/MalykhSergey/T1-hw5/tree/master.
```json
[
  {
    "subjectName": "testuser",
    "serialNumber": "f1c2df72-2641-442f-a930-df63e6617aab",
    "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkHtKRGWQd5Goa9RldxIVZPBHMx8AW828n8+zmzex3F2SRWqItRm4L7AisooIOKIkhXEzLokDEmo6NfMhKydHBJl9KEczfQnKq+8v2e1109BwigDYnvMz5dooQe8BoLu7moFXC25H9or1YssnBVSUdh5masrklksOLkKolDtn1XqKUDlk00iu4dJJzWZUJAoRLtK+phtD8A9aUT3JamFCky41oRQThoJLzwVrW29q6GQQDlyuy2GyCgv9nERYyn2suGvnXE+p/pRQjNBehKnBVLojv2udMAovvWx4Z9cJpEg4tytwuJ5V3D9bESOwDraFHGetybGOVQybi5CVsDaRYQIDAQAB",
    "keyAlg": "RSA",
    "issueDate": "2025-07-27T05:38:52.228+00:00",
    "expiryDate": "2026-07-27T05:38:52.228+00:00",
    "signature": "HUt+AF0ypIAwMQJRkvWllysUL+F63JSmfYZk8T/1MxdZzlaSLElbCrJbXuTE+qA2sIoIDNhyshW0127ONFNkN9phBFAH5Y9LS+r4ckNwYbrYqZrfmVOPN/GUat7m7JAkDYoKp21JGKj3GyNMkA7g5lOakG15DryCo4ixbzfZjUi3Hhm7SoJbgZ4s6l9uF0sGqNOZY1lQcSuVMlxtVnxcJT5+YNJ7gOvCqZS4f5KaC+zXGOH/6SyhBLoBvZLIkJmjDdDMzOsYjOjuS67CzUFHl/gpF8KiYV7nMNKVyi/nX/XOCD3dnm3Nfwtf6dzAlM5F57ll0rzJqWSdidYL+qvCQw==",
    "signAlg": "RSASSA-PSS",
    "issuerName": "AuthService"
  },
  {
    "subjectName": "AuthService",
    "serialNumber": "590b2479-2da7-4ea8-a1b7-31b91b68a9b3",
    "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxW584utvFsYg1cCOMw0Y8dHakIS85i8GtWsmwgBBkWANAXjyNoKlsHiOQMncP3r2le4DSpGi2x3lG8ddmarEv1dnahWYWe7ZqSz3OEkPfQyFsKcBCiRbJdA+M9ohLv8A67UjPHyrlxiJ+5APUdU2fa+rli1VRktRR9BC+zoos0tNt+r/V+zhx+1noa/j1weM0GPBVzRzW8Q5b+OJ5YA6oCeS5wGpWDjpw2jTIj2o/T3AtZ8hqlnKyw2gyslAZ/3d3CC7wAmDt/jOs3oist4+lJ9O/VYKPHERPkc8lVkMS4p+Eu+JnPcEF9yK3ACiA0wr7zp1V19dVAeE9ceM4W5nzQIDAQAB",
    "keyAlg": "RSA",
    "issueDate": "2025-07-27T05:35:32.363+00:00",
    "expiryDate": "2035-07-25T05:35:32.363+00:00",
    "signature": "AI7uZHsOVEXn2weaFM7U9mC24kqGN7JOIFziQMpDb81hgDaM+302KsglUsGj5kCI/pcv44qFSt2oem671/3oi3fa9lhyFNnQ5aavT1BPUZQtqLMR5gNnvPf6Q+EGFijv8lnSdbf17S3rJ+2GBiEv/gx5ClpBKuQdsmq5GN/q4pRE5D4ao9WxWxKnFrZk7zIuvA5bPDm4NwMoqHfnaPYQ0jiFvn2QALDmUKR9TxqIA/sct+YcCc1/Gsyq4QhNxv9ip9WZGzExLUva7dK61UAPqeuA53/OQqHc84lPfPz8e1POlsIgxIWLoDMJxX+sFcbB3znZq3pg/+66/OXE8MNMyg==",
    "signAlg": "RSASSA-PSS",
    "issuerName": "AuthService"
  }
]
```

Далее общение между участниками идёт в формате засекреченных сообщений:
```json
{
  "encryptedData": "0tx0ylwaMXtydFo+Aa3OwFb+ylUD+2pj4Bfn7JlKCDA=",
  "encryptedSessionKey": "Fax8/qszKahh7CzFqlt4LCzHO0XzvioT4fMn3ymM4A8rCHWs5KRAaigyX94Ssmvi0axAb4f6f+OXKWgZsgUUGRpQZvmVnLEJWpx6bzzgdtFSpwdWGpzQ3B1HBKbTyWhRgBtbxoObFM6+fVTsLgzpfYDdH37UC+1PKjB2DQybNX+yOOtIjO2seiYQIcR7mUFwotjuy+shZ50yx1hpzdbMcu8mVRDz+LgiF2njmGuT9Bcub0nKc7mg0Pb/SpcRVz4KU5OR6WeT72PUrsjCAohQ/m0u6gSP6pmq1i/GEFSLNKh7FUAgnkR4jaP5HvYcssJXej2IKuY04jxL0H3QwR+EhA==",
  "sign": "AN4yV4F3gy8O6PHjoF0o51CeL3z18Fw8VnZEL2JQWACczxZ8MMySbf/pwJgnS1tpMR1ybGAhWjravK20ZQEx6nnCdK6dM3hqLyWmb/qmPYvDgSvneJGhclFPW6vrdj13T0sADkEEQMIuc4uWQgU2luJVGaCzA/EFs2wo6wdCbC52D541WOq5KSkbfeAB4fxTD/CpSQXcKH0LkyoRteAC4gKj2qWCV32rFJkIpt6scgGprF/CD4TOnOQ2klaC4wUTZxaTwqOrVwu3OvLSAL/gE0InSQRkiGoa7PZfTMWEVCxttOTii9VJRVKpcuMYqee55sU49Ko2JWMn2MHn9Mi+gg==",
  "certificateDTO": {
    "subjectName": "f85f8561-d5fa-403a-af87-a186555c0540",
    "serialNumber": "f47be721-2863-419d-bbd5-127826bd324e",
    "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAk2UQATw4oaDi8CszOHOt7gvO0dG4wArqzfsXzrCHXqZ+Z494Fz5LxdRD28TmTqRI2PJ27L6xuDwpD5BEpYBwftq67L0wFO7QA17q5ihEvDqEja8fmfVdlufKOQ/+sRmQtn40H3+sxxcxUVjCXA9v9DK9d06/xi4HSoeBvZ7nRu9ixE/hAg3CHpR1P2NoP98DaZbn0RmEYDTFRkJTvFtkmpsHxblccUQnCUQ8w2CpvUl2owIlbZThOlk06gqao6TLoN/Kwan3MuAXZtyBCUQkrjyC2/ybsoEcki9aYJrktahhXADg86xGeI9NzJg6Qh3lOClQMYaAyxm6dfIOqloJKwIDAQAB",
    "keyAlg": "RSA",
    "issueDate": "2025-07-27T05:47:39.085+00:00",
    "expiryDate": "2026-07-27T05:47:39.085+00:00",
    "signature": "3v57HFWPC8XoY6pN/dQq4Lvb7WOLeAYk9Lp/2TrI/aW3F1XMaHjtCfiqtfPJX3nBbfrpO8R3HuwSvG9y7hg9vNXgBN/ULLHwbP73+0Tg4VzJWU2Ta1lVwdSTLqRUE9shsMd77AlG/uR6jvkDAfCGWKTaB1xxcnfjx850NlD/P+Ocz7XprNm9HXlU2uwFS8zrOycWFfWrnVCIjz0ZO3tDkFz5mxIWd3PPuXJZ+/XknjM1MEaBbjLIkyz4punj9E16iZLYITsXkzvogT324y0HvSo6tMw+vhbzCzWekaKBX2pWm8gizmh0FY6gtmlvivbu5OId95PHVJ4X/jqdPdmHMA==",
    "signAlg": "RSASSA-PSS",
    "issuerName": "AuthService"
  },
  "signAlg": "RSASSA-PSS",
  "signProperties": {
    "trailerField": 1,
    "digestAlgorithm": "SHA-256",
    "mgfalgorithm": "MGF1",
    "mgfparameters": {
      "digestAlgorithm": "SHA-256"
    },
    "saltLength": 32
  },
  "keyGenAlg": "AES",
  "asymmetricAlg": "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
  "symmetricAlg": "AES/CBC/PKCS5Padding"
}
```

Для проверки работоспособности системы реализован системный тест (вручную это проверять слишком сложно):
```java
@Test
    @DisplayName("Полный цикл: регистрация, проверка, отзыв")
    void testRegistrationAndCertificateLifecycle() throws Exception {
        RegisterDTO registerDTO = createRegisterDTO();

        // Выполняем регистрацию и получаем сертификаты
        CertificateDTO[] certs = performRegistration(registerDTO);
        Certificate senderCert = certs[0].getCertificate();
        Certificate centerCert = certs[1].getCertificate();

        // Проверяем информацию о пользователе
        verifyUserInfo(registerDTO, senderCert, centerCert);

        // Получаем сертификат собеседника
        verifyFetchSubjectCertificate(registerDTO.userName(), centerCert, certs[0]);

        // Проверяем верификацию сертификата
        verifyCertificateVerification(certs[0], centerCert);

        // Отзываем сертификат и проверяем доступ
        revokeCertificate(registerDTO.userName());

        // После отзыва сертификата доступ должен быть запрещен
        assertAccessDeniedAfterRevoke();
    }
```

Аутентификация пользователя, как и ранее выполняется в фильтре Spring security. Однако теперь также после
этого фильтра подменяется тело запроса, чтобы контроллеры получали уже дешифрованные и проверенные данные.

```java
public class AuthTokenFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            if (request.getHeader("SecuredMessageProtocol") != null) {
                CipherMessageDTO cipherMessageDTO = objectMapper.readValue(request.getInputStream().readAllBytes(), CipherMessageDTO.class);
                byte[] decrypted = authService.decryptAndVerify(cipherMessageDTO);
                UserDTO user = authService.loadUserDTOByName(cipherMessageDTO.getCertificateDTO().getSubjectName());
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        user, null, user.getRoles());
                SecurityContextHolder.getContext().setAuthentication(authentication);
                request = new DecryptedHttpServletRequest(request, decrypted);
            }

        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }
}
```

## Примечание

1. Сервис является *доказательством идеи* системы безопасного общения на основе сертификатов.

2. Предполагается, что пользователи регистрируется в обход незащищённого канала или вовсе офлайн.
   Иначе шпион может притвориться центром сертификации.

