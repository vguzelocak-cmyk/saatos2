# DriverLab: Linux üzerinde Windows sürücüsü uyumluluk araştırması

Amaç, `vgk.sys` gibi Windows çekirdek sürücülerinin Linux'ta çalıştırılması
için gerekenleri araştırmak. Proje, PE yükleyicisi ve Windows x64 ABI ile
çağrılan bir NT uyumluluk kütüphanesi içerir. 50 farklı işlev, modül
eşlemeleriyle birlikte 51 export kaydı üzerinden kullanılabilir.
Desteklenen importları kullanan küçük test sürücüleri Linux kullanıcı
alanında yürütülebilir. **Tam Windows çekirdeği değildir; Vanguard/Valorant
çalıştırmaz.** İşlevlerin kapsamı ve sınırları [NT runtime belgesindedir](docs/nt-runtime.md).

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
python3 examples/make_kernel_driver.py /tmp/driverlab-kernel-test.sys
python3 -m driverlab.run /tmp/driverlab-kernel-test.sys --execute
```

Örnek dosya zaten varsa ve aynı içeriğe sahipse tekrar kullanılır. Farklı
içerik varsa üretici dosyayı ezmeden hata verir.
Başarılı çıktıda `driver_entry_called: true`, `ntstatus: "0x00000000"`
ve `nt_success: true` görülür. Bu sonuç gerçek makine kodunun çalışmasıyla
elde edilir: yeni örnek, IAT üzerinden 9 importu kullanarak bellek ayırır,
veri karşılaştırır, belleği serbest bırakır, UTF-16 dizesi hazırlar,
auto-reset event kurar/sinyaller/bekler ve HAL zaman sayacını sorgular.
Dinamik fonksiyon adresi de gerçek export adresiyle karşılaştırılır.
Başarısız bir doğrulama, sürücünün başarısız NTSTATUS döndürmesine yol açar.
Eski `examples/make_driver.py` örneği, ayrıca temel ABI ve mutlak adres
düzeltmelerini sınamak için korunmuştur.

Çıktıda `kernel_compatibility: "user-mode-subset"`,
`kernel_exports_available: 51` ve `resolved_import_count: 9` görülür.
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
callback, I/O ve kalıcı servis yaşam döngüsü uygulanmamıştır.

Desteklenmeyen NT importları, TLS, delay-load, CLR ve yazılabilir/yürütülebilir
bölümler içeren dosyalar yürütülmeden reddedilir.
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
2. PE yükleme, relocation, import çözümleme ve Windows x64 çağrı kuralları
   uygulandı; kapsamı sınırlı test sürücüleriyle doğrulandı.
3. Gereken NT çekirdek davranışlarını uygulamak: nesneler, bellek,
   senkronizasyon, IRQL, I/O, callback ve kullanıcı alanı servis iletişimi.
   Bunları sabit başarı döndüren taklitlerle doldurmak uyumluluk sağlamaz.
4. Sürücünün donanım/çekirdek beklentilerini ve Linux ile uygulanabilirliğini
   değerlendirmek. Linux kullanıcı alanında bir Windows çekirdeği mevcut değildir.
5. Riot'un destek ve istemci kabul koşullarını ayrıca çözmek. Bir sürücünün
   giriş fonksiyonuna ulaşmak, Valorant'ın çalıştığını kanıtlamaz.

NT işlevlerinin bir bölümü ve import çözümleme uygulandı. I/O, registry,
MDL/fiziksel bellek, CNG kriptografisi, kernel callback'leri, Windows
istisna yönetimi ve süreç nesne yöneticisi yoktur. Gerçek Vanguard dosyasıyla
çalışma testi yapılmadı. Testler; PE import çağrılarını, bellek ve UTF-16
işlemlerini, çok iş parçacıklı kilitleri/olayları, rundown korumasını,
zamanı, dinamik fonksiyon çözümlemeyi, ABI ve relocation davranışını,
NTSTATUS aktarımını, çökme ve zaman aşımını doğrular.
