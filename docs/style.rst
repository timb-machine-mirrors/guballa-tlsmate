Customizing the scanner style
=============================

When using the colored text output of the scanner, settings are displayed in
different colors, depending whether the profile setting is regarded as "good" or not.

By default, the following colors are used:

- no color: neutral
- red: bad, unacceptable behavior
- yellow: setting, which does not meet the expectation
- green: setting is regarded as good

.. note:: By intention ``tlsmate`` restricts itself to these classifications
   only. Using more colors would be possible, but the benefit is questionable,
   as the assessment in many cases is debatable anyway.

The default style profile is rather strict and does not make any compromise
from security perspective. In reality, things are not that easy and a balance
must be found between security and e.g. performance or interoperability. As a
result there is not that one and only profile which should be taken as granted
for each and every use case.

Therefore, ``tlsmate`` allows to customize some text provided in the output
as well as the classification and the colors used to indicate the assessment.

The location of the style file (YAML-format) used by default by ``tlsmate`` is
provided in the "Basic scan information" section of the output. Via the CLI
argument ``--style`` it is possible to use any other customized style file instead.
This can be useful to support other assessments, or to use another color scheme
(e.g., to support color blind people).
