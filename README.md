# DriverLab: Linux üzerinde Windows sürücüsü uyumluluk araştırması

Amaç, `vgk.sys` gibi Windows çekirdek sürücülerinin Linux'ta çalıştırılması
için gerekenleri araştırmak. Proje, statik analiz aracına ek olarak küçük,
import içermeyen test sürücülerinin giriş kodunu Linux kullanıcı alanında
yürütebilen deneysel bir PE yükleyicisi içerir. **Windows çekirdeğini
uygulamaz; Wine alternatifi değildir ve Vanguard/Valorant çalıştırmaz.**

## Kullanım

Analiz için Python 3.10+ yeterlidir. Mevcut depo kopyasında çalıştırın:

```sh
cd /workspace/saatos2
python3 -m driverlab /dosya/yolu/vgk.sys
python3 -m driverlab /dosya/yolu/vgk.sys --json > /tmp/vgk-report.json
python3 -m unittest discover -s tests -v
```

`/dosya/yolu/vgk.sys` örnek bir yoldur; gerçek dosyanızın yolunu kullanın.
Bu depoda gerçek `vgk.sys` bulunmuyor. Analiz komutu sürücüyü indirmez,
değiştirmez veya çalıştırmaz. Çalışma, eski dosyaların silindiği güncel `main`
dalı üzerine kuruludur.

Rapor; SHA-256, mimari, alt sistem, giriş adresi ve PE32+ standart import
tablosundaki modül/fonksiyonları içerir. İsim ve ordinal importları okunur.
Bozuk dosyalar, eşlenemeyen adresler ve sonlandırılmamış tablolar hata verir.
Başarı kodu `0` yalnızca analizin tamamlandığını, `2` analiz hatasını belirtir;
hiçbiri sürücünün çalışabileceği anlamına gelmez. Delay-load importları
ayrıştırılmaz; varsa raporda belirtilir. İmza doğrulaması yapılmaz.

## Gerçek kod yürütme deneyi

Gereksinimler: x86-64 Linux, Python 3.10+, `cc` veya `gcc` ve standart C
geliştirme başlıkları. Python sanal ortamı veya ek Python paketi gerekmez.
Yerel C köprüsü her çalıştırmada geçici klasörde derlenir; normal çıkışta
silinir. Worker zorla durursa geçici derleme dosyaları kalabilir.
Linux'taki proje klasöründe şu komutlarla deneyin:

```sh
git pull --ff-only origin driverlab-foundation
python3 examples/make_driver.py /tmp/driverlab-test.sys
python3 -m driverlab.run /tmp/driverlab-test.sys --execute
```

Örnek dosya zaten varsa üretici onu ezmez; başka bir dosya yolu seçin.
Başarılı çıktıda `driver_entry_called: true`, `ntstatus: "0x00000000"`
ve `nt_success: true` görülür. Bu sonuç gerçek makine kodunun çalışmasıyla
elde edilir: test kodu Windows ABI parametrelerini kontrol eder ve adresi
yükleyici tarafından düzeltilmiş bir işaretçiden dönüş durumunu okur.
Sonuçta `windows_kernel_implemented: false` da açıkça belirtilir.

Yükleyici PE bölümlerini eşler, DIR64 relocation kayıtlarını uygular,
bellek korumalarını ayarlar ve Microsoft x64 ABI ile `DriverEntry` çağırır.
Girişe temel alanları doldurulmuş bir `DRIVER_OBJECT` ile UTF-16
`UNICODE_STRING` verilir. Bu nesneler tam bir NT nesne yöneticisi değildir.
Sürücünün giriş fonksiyonu döndükten sonra bellek bırakılır; unload,
callback, I/O ve kalıcı servis yaşam döngüsü uygulanmamıştır.

NT importları, TLS, delay-load, CLR ve yazılabilir/yürütülebilir bölümler
desteklenmez; bunlara ihtiyaç duyan dosyalar yürütülmeden reddedilir.
Windows istisna yönetimi uygulanmaz. Sürücü imzaları doğrulanmaz.
`vgk.sys` raporundaki çekirdek bağımlılıkları nedeniyle bu yürütücüde çalışmaz.

`--execute`, gerçek yerel kodu mevcut kullanıcı yetkileriyle çalıştırır.
Yalnızca güvendiğiniz test koduyla kullanın; worker işlemi bir güvenlik
sandbox'ı değildir. Root gerekmez ve root olarak çalıştırmayın.
Varsayılan worker zaman sınırı 5 saniyedir (`--timeout 10` ile değişir).
Zaman sınırında worker işlem grubu durdurulur; bu, kodun oluşturmuş
olabileceği dosya veya diğer yan etkileri geri almaz.
Çıkış kodları: `0` NT_SUCCESS, `1` sürücünün döndürdüğü başarısız NTSTATUS,
`2` yükleme/çalıştırma hatası veya zaman aşımı.

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

Analiz ve import içermeyen örnekler için PE yürütme temeli uygulandı.
NT çekirdek API'leri ve import çözümleme uygulanmadı. Diğer aşamaların
uygulanabilirliği kanıtlanmadı; bu proje onların tamamlanacağını vaat etmez.
Gerçek Vanguard dosyasıyla çalışma testi yapılmadı. Testler, üretilen PE
örnekleriyle ayrıştırmayı, gerçek kod yürütmeyi, ABI parametrelerini, adres
düzeltmelerini, NTSTATUS aktarımını, çökme ve zaman aşımını doğrular.
