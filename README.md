# DriverLab: Linux üzerinde Windows sürücüsü uyumluluk araştırması

Amaç, `vgk.sys` gibi Windows çekirdek sürücülerinin Linux'ta çalıştırılması
için gerekenleri araştırmak. **Bu sürüm bir Wine alternatifi veya sürücü
çalıştırıcısı değildir; Vanguard/Valorant desteği sağlamaz.** İlk aşama,
gerçek bir sürücü dosyasından statik bağımlılık raporu çıkarmaktır.

## Kullanım

Python 3.10+ dışında bağımlılık yok. Mevcut depo kopyasında çalıştırın:

```sh
cd /workspace/saatos2
python3 -m driverlab /dosya/yolu/vgk.sys
python3 -m driverlab /dosya/yolu/vgk.sys --json > /tmp/vgk-report.json
python3 -m unittest discover -s tests -v
```

`/dosya/yolu/vgk.sys` örnek bir yoldur; gerçek dosyanızın yolunu kullanın.
Bu depoda gerçek `vgk.sys` bulunmuyor. Araç sürücüyü indirmez, değiştirmez,
yüklemez veya çalıştırmaz. Çalışma, eski dosyaların silindiği güncel `main`
dalı üzerine kuruludur.

Rapor; SHA-256, mimari, alt sistem, giriş adresi ve PE32+ standart import
tablosundaki modül/fonksiyonları içerir. İsim ve ordinal importları okunur.
Bozuk dosyalar, eşlenemeyen adresler ve sonlandırılmamış tablolar hata verir.
Başarı kodu `0` yalnızca analizin tamamlandığını, `2` analiz hatasını belirtir;
hiçbiri sürücünün çalışabileceği anlamına gelmez. Delay-load importları
ayrıştırılmaz; varsa raporda belirtilir. İmza doğrulaması yapılmaz.

## Gerçek bir çalışma katmanı için gerekenler

1. Gerçek sürücünün bağımlılıklarını ve hedef Windows sürümünü belirlemek.
   Statik rapor başlangıçtır; dinamik çözülen fonksiyonları göstermez.
2. PE yükleme, relocation, import çözümleme ve Windows x64 çağrı kurallarını
   kontrollü bir yürütme ortamında uygulamak.
3. Gereken NT çekirdek davranışlarını uygulamak: nesneler, bellek,
   senkronizasyon, IRQL, I/O, callback ve kullanıcı alanı servis iletişimi.
   Bunları sabit başarı döndüren taklitlerle doldurmak uyumluluk sağlamaz.
4. Sürücünün donanım/çekirdek beklentilerini ve Linux ile uygulanabilirliğini
   değerlendirmek. Linux kullanıcı alanında bir Windows çekirdeği mevcut değildir.
5. Riot'un destek ve istemci kabul koşullarını ayrıca çözmek. Bir sürücünün
   giriş fonksiyonuna ulaşmak, Valorant'ın çalıştığını kanıtlamaz.

Şu an yalnızca ilk aşamanın analiz aracı uygulandı. Diğer aşamaların
uygulanabilirliği kanıtlanmadı; bu proje onların tamamlanacağını vaat etmez.
Gerçek sürücüyle çalışma testi yapılmadı. Testler yapay PE örnekleriyle
ayrıştırıcının işlevini ve hatalı girdi davranışını doğrular.
