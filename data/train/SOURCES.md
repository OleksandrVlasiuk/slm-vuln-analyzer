# Джерела train_corpus/

Репозиторії, з яких побудовано навчальну вибірку для дистиляції
(`data/train/findings_train.csv`). Для кожного вказано коміт, зафіксований на
момент сканування. У таблиці лише успішно оброблені джерела: репозиторії, які
не вдалося клонувати, у вибірку не входять.

| Репозиторій | Коміт | Статус |
|---|---|---|
| OWASP/railsgoat | `f5951f13089d85c979de09e7da3c8c0fb982f94a` | OK |
| snoopysecurity/dvws-node | `eb6e2886f2206b88bf709fe1fa311adc3ae3c34f` | OK |
| digininja/DVWA | `b496a5d3de6b967410155e1b7d3e51e9d035eb22` | OK |
| OWASP/wrongsecrets | `58a7ac0767c4602e61d28da5ac580e423e94fca2` | OK |
| we45/Vulnerable-Flask-App | `b6a4f97afd466e83e1f60781494252dec1c37039` | OK |
| appsecco/dvna | `9ba473add536f66ac9007966acb2a775dd31277a` | OK |
| adeyosemanputra/pygoat | `19d17cc8874861142b330636d068bbde54e86b85` | OK |
| apache/airflow | `29f48b532e5d97348a3b837b0125bdcf14e03792` | OK |
| getsentry/sentry | `e917c50c2413cd5082524c3f98791eb035fd38de` | OK |
| saleor/saleor | `6e2dc35d0cbc7de85ce3503d5e872e2f672ba70e` | OK |
| home-assistant/core | `3a74193c419e66a9a3665407633e4c90b3f4d555` | OK |
| ansible/ansible | `5467293624690dbb5ecf8dc8f442fa3e3204fbc5` | OK |
| strapi/strapi | `34fdea8fb4e11afc475a0ffdc14311cce09ddded` | OK |
| n8n-io/n8n | `9da3b7479f1997757a43c6cf5350687677f92b57` | OK (перший клон падав на checkout через довгі шляхи Windows; вдруге з `git -c core.longpaths=true`) |
| directus/directus | `dc922b790a15949e8abfce9c1f4523d4e5f89492` | OK |
| nestjs/nest | `a3a31b96436a0c5fc33266a19c02cfa4fd2c03c0` | OK |
| expressjs/express | `53d4a0d606c0388f764f192b306ce0e90200e7e8` | OK |
| zulip/zulip | `675c8cf9927e48b922afd4dd31dad68bb505928f` | OK |
| openedx/edx-platform | `d1cdd628f10c638e2abd79c573b6566c04b2d732` | OK |
| WeblateOrg/weblate | `c5204b9cec73f2358d831667c23b0456baef8af6` | OK |
| getredash/redash | `8f6b15d30da433ae881dd6376a38df17bb6c2663` | OK |
| apache/superset | `8e66145cfed5ca0584cc71c7795814a2752522e6` | OK |
| wagtail/wagtail | `de19d7c21c978dc798459663a4c36fe672dceca6` | OK |
| django-oscar/django-oscar | `0dfeaa797f4ed3c733e0449e70bc0a1da1a37203` | OK |
| Netflix/dispatch | `dd2837e82a0bf5565b1b4b4b91ea30b7262d4061` | OK |
| mozilla/addons-server | `c2404fb30b6f4f0d3935c47fe0e77fe01de0b0e8` | OK |
| pretalx/pretalx | `18e85418f719e1ab54212a07367863b695f72b0f` | OK |
| celery/celery | `1a3ea2eb8b4e83085754ac4b0de397ef4cbfa31b` | OK |
| scrapy/scrapy | `a527168ad0888a54b665a6d00a45c720a956e1c0` | OK |
| nocodb/nocodb | `588d51381ec28a8e4811450cd7155ccd51bba8c6` | OK |
| appsmithorg/appsmith | `172b7c1c8f7e4b16c708fbd9341544b059a2d5c3` | OK |
| TryGhost/Ghost | `151d2619198bd74a94368726de6712471f8c28bc` | OK |
| OWASP/NodeGoat | `c5cb68a7084e4ae7dcc60e6a98768720a81841e8` | OK |
| parse-community/parse-server | `6d92204b554154eaef395e513da8324984b25ebb` | OK |
| keystonejs/keystone | `5d58de638a757a1a50dbb68cfff47fa1000afb23` | OK |
| payloadcms/payload | `06f05f7db3db5a2a7a97e76402cc5e3f949127c7` | OK |
| medusajs/medusa | `f8dce55556a1e68d6ea9b2fb88852b2a76fbd73c` | OK |
| twentyhq/twenty | `95e2a851ca4b9ed032aae225a440f1c733bb763a` | OK |
| formbricks/formbricks | `cd1c6a3d79d6d3dca9ee97e44f2e62f44f8dc474` | OK |
| pulp/pulpcore | `b846b86eb9f82cd9224e29edc025603415d3f8d8` | OK |
| ansible/awx | `9fdfc95d374347cec95847a29839dd766a482c4f` | OK |
| freedomofpress/securedrop | `ec5a801f5195961630ef7c0ec6ce8dc38bd3cd87` | OK |
| learningequality/kolibri | `815292f62c50a992f1f7d45bdda87f124ff70e6f` | OK |
| inventree/InvenTree | `7c246aedb05ecb1c45fe03ad77ec7a2c8e2f0c99` | OK |
| OpenSlides/OpenSlides | `d87969afc98477d0575d85af12e980754e42a776` | OK |
| ArchiveBox/ArchiveBox | `da9b867dafc7777d114b93f6f951074a1a05497a` | OK |
| DataDog/integrations-core | `47ac6e1950cd92ae63561b9e395556f2d65b38ef` | OK |
| PrefectHQ/prefect | `9795fc271ce582dbe94165cdc43a9119bc3828f6` | OK |
| kiwitcms/Kiwi | `99ce3c593882974845508aaf059d353e1febca88` | OK |
| django-cms/django-cms | `aaf010b23a16ef95e994ba2d5b99cccc9d650558` | OK |
| comfyanonymous/ComfyUI | `19e1058f4c445ef74047e77a23f9ca7684c1e4b6` | OK |
| outline/outline | `b70bb4d02d3acc8b5404d2ac8bb655d1850f8332` | OK |
| tinacms/tinacms | `df351832c37fd0efaf5a06cb6cde9a5ec404201e` | OK |
| RocketChat/Rocket.Chat | `d6956ab50f206a47d57c45c6e4d59041828ebcce` | OK |
| mattermost/mattermost | `012e6dda5d685760f8e91c1f9fb54b3a9a789079` | OK |
| elastic/kibana | `9ed8129a7b5cb4e314df9b8a29611867ad022e95` | OK |
| grafana/grafana | `e3aab369030f964913dcc0db866b441d1132c7e1` | OK |
| novuhq/novu | `0d24979fce32fadd6d07b0657bf0b236de7ed6e7` | OK |
| immich-app/immich | `eb84a5ad7f3b2f01cf429089b338f8949a0269ed` | OK |
