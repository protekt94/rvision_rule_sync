# Сравнение custom с пакетами SIEM

Прямое сравнение без BASE. Различия могут быть намеренными кастомизациями.
Знаки − показывают custom, знаки + — SIEM. Автоматического слияния нет.
`id`, `rid`, `test`, `tests` исключены из сравнения. Отмеченные правки учитываются целиком.

| Статус | Количество пар правило/пакет |
|---|---:|
| NO_CHANGE | 0 |
| METADATA_ONLY | 0 |
| REVIEW_REQUIRED | 1 |
| ORPHANED | 0 |

## SOC-D-DEMO1 ← RV-D-DEMO1: REVIEW_REQUIRED

Пакет: demo\.roc (снимки: package-001)

Различающиеся блоки: metadata, on\_correlate

### Мои критичные изменения

Строки отсчитываются внутри текстового блока, включая строки маркеров.

**on\_correlate, строки 1–3**

```vrl
.groupedBy = ["example_custom_host"]

```

### on\_correlate — содержит мои критичные изменения

```diff
--- CUSTOM
+++ SIEM
@@ -1,5 +1,3 @@
 on_correlate: !vrl |
-  # начало моих изменений
-  .groupedBy = ["example_custom_host"]
-  # конец моих изменений
+  .groupedBy = ["example_host"]
   .description = "Synthetic event"

```

### metadata

```diff
--- CUSTOM
+++ SIEM
@@ -1,9 +1,9 @@
 metadata:
   name: Synthetic example rule
-  version: 1.0.4
+  version: 1.0.3
   date: '2026-01-01'
-  author: Example Maintainer
+  author: Example Author
   description: Synthetic data for testing the comparison tool.
   known_false_positives:
-  - Synthetic condition A
-  - Synthetic condition B
+  - Synthetic condition A.
+  - Synthetic condition B.

```

