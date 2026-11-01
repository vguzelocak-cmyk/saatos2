# DriverLab: Linux üzerinde Windows sürücüsü uyumluluk araştırması

Amaç, `vgk.sys` gibi Windows çekirdek sürücülerinin Linux'ta çalıştırılması
için gerekenleri araştırmak. Proje, PE yükleyicisi ve Windows x64 ABI ile
çağrılan bir NT uyumluluk kütüphanesi içerir. İşlev ve veri sembolleri için
toplam 108 export kaydı kullanılabilir.
Desteklenen importları kullanan küçük test sürücüleri Linux kullanıcı
alanında yürütülebilir. **Tam Windows çekirdeği değildir; Vanguard/Valorant
çalıştırmaz.** İşlevlerin kapsamı [NT runtime](docs/nt-runtime.md) ve
[I/O, registry, kriptografi ve bellek](docs/native-services.md) ile
[NT uzantıları](docs/nt-extensions.md) belgelerindedir.

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

Gereksinimler: x86-64 Linux, Python 3.10+, `cc` veya `gcc`, standart C
geliştirme başlıkları ve OpenSSL 3 geliştirme dosyaları (`libcrypto`).
Debian/Ubuntu'da `build-essential libssl-dev`, Fedora'da `gcc openssl-devel`,
Arch'ta `base-devel openssl` paketleri bunları sağlar.
Python sanal ortamı veya ek Python paketi gerekmez.
Yerel C köprüsü her çalıştırmada geçici klasörde derlenir; normal çıkışta
silinir. Worker zorla durursa geçici derleme dosyaları kalabilir.
Linux'taki proje klasöründe şu komutlarla deneyin:

```sh
git pull --ff-only origin driverlab-foundation
python3 examples/make_services_driver.py /tmp/driverlab-services-test.sys
python3 -m driverlab.run /tmp/driverlab-services-test.sys --execute
```

Örnek dosya zaten varsa ve aynı içeriğe sahipse tekrar kullanılır. Farklı
içerik varsa üretici dosyayı ezmeden hata verir.
Başarılı çıktıda `driver_entry_called: true`, `ntstatus: "0x00000000"`
ve `nt_success: true` görülür. Bu sonuç gerçek makine kodunun çalışmasıyla
elde edilir: servis örneği, IAT üzerinden 22 importu kullanarak dosya
yazıp okur, volatile registry anahtarı/değeri oluşturup sorgular, SHA-256
sonucunu bilinen vektörle karşılaştırır ve süreç sayfalarını kilitleyip MDL
üzerinden aynı belleği kullanır.
Başarısız bir doğrulama, sürücünün başarısız NTSTATUS döndürmesine yol açar.
`examples/make_driver.py`, temel ABI ve mutlak adres düzeltmelerini;
`examples/make_kernel_driver.py`, olaylar/bellek/UTF-16/HAL işlevlerini
sınamak için korunmuştur.

Çıktıda `kernel_compatibility: "user-mode-subset"`,
`kernel_exports_available: 108` ve `resolved_import_count: 22` görülür.
`windows_kernel_implemented: false` tam Windows çekirdeğinin bulunmadığını
belirtir; eklenen kısmi NT işlevlerini yok sayan bir durum göstergesi değildir.

Yükleyici PE bölümlerini eşler, DIR64 relocation kayıtlarını uygular,
bellek korumalarını ayarlar ve Microsoft x64 ABI ile `DriverEntry` çağırır.
Girişe temel alanları doldurulmuş bir `DRIVER_OBJECT` ile UTF-16
`UNICODE_STRING` verilir. Bu nesneler tam bir NT nesne yöneticisi değildir.
Import adresleri, modül ve sembol adına göre NT kütüphanesinden çözülüp IAT'ye
yazılır. Eksik bir import varsa giriş fonksiyonu çağrılmaz ve eksik semboller
raporlanır. Ordinal importlar için runtime eşlemesi yoktur.
Sürücünün giriş fonksiyonu döndükten sonra bellek bırakılır; unload,
  callback, device-stack I/O ve kalıcı servis yaşam döngüsü uygulanmamıştır.

Desteklenmeyen NT importları, TLS, delay-load, CLR ve yazılabilir/yürütülebilir
bölümler içeren dosyalar yürütülmeden reddedilir.
Windows istisna yönetimi uygulanmaz. Sürücü imzaları doğrulanmaz.
`vgk.sys`, kalan çekirdek bağımlılıkları ve eksik kernel davranışları
nedeniyle bu yürütücüde çalışmaz.

Dosya I/O'su varsayılan olarak worker'a özel geçici namespace kullanır.
`\??\C:\a.bin`, bu namespace'in `files/C/a.bin` yoluna eşlenir. Dosyaları
saklamak için `--state-dir /ayrı/bir/çalışma/dizini` verilebilir; bu dizinde
gerekli `files/C` klasörleri oluşturulur. Registry bu seçenekle de worker'a
özeldir ve kalıcı değildir; non-volatile anahtar oluşturma desteklenmez.
Bellek API'leri süreç belleğini `mlock` ile kilitler; gerçek fiziksel adres,
DMA sayfası, Windows kernel sayfası veya ring-0 yürütme sağlamaz.

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
2. PE yükleme, relocation, import çözümleme ve Windows x64 çağrı kuralları
   uygulandı; kapsamı sınırlı test sürücüleriyle doğrulandı.
3. Gereken NT çekirdek davranışlarını uygulamak: nesneler, bellek,
   senkronizasyon, IRQL, I/O, callback ve kullanıcı alanı servis iletişimi.
   Bunları sabit başarı döndüren taklitlerle doldurmak uyumluluk sağlamaz.
4. Sürücünün donanım/çekirdek beklentilerini ve Linux ile uygulanabilirliğini
   değerlendirmek. Linux kullanıcı alanında bir Windows çekirdeği mevcut değildir.
5. Riot'un destek ve istemci kabul koşullarını ayrıca çözmek. Bir sürücünün
   giriş fonksiyonuna ulaşmak, Valorant'ın çalıştığını kanıtlamaz.

NT işlevlerinin bir bölümü ve import çözümleme uygulandı. Senkron dosya I/O,
volatile registry, seçili CNG hash/imza işlemleri ve süreç içi MDL desteği
vardır. IRP/IOCTL/device stack, fiziksel/kernel bellek, kernel callback'leri,
Windows istisna yönetimi ve süreç nesne yöneticisi yoktur. Gerçek Vanguard dosyasıyla
çalışma testi yapılmadı. Testler; PE import çağrılarını, bellek ve UTF-16
işlemlerini, çok iş parçacıklı kilitleri/olayları, rundown korumasını,
zamanı, dosya round-trip/erişim/paylaşım kurallarını, registry yaşam
döngüsünü, SHA-256/HMAC test vektörlerini, RSA/ECDSA doğru/yanlış imzalarını,
MDL sayfa kilitlemesini, dinamik çözümlemeyi, ABI/relocation davranışını,
NTSTATUS aktarımını, çökme ve zaman aşımını doğrular.
