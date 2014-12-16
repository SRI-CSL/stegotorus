# StegoTorus pages with Jekyll/Skinny Bones

We are using Jekyll with GitHub Pages and in particular the Skinny Bones theme.

To learn more about how to use the theme check out the [Skinny Bones demo](http://mmistakes.github.io/skinny-bones-jekyll/).

## Developing these pages

Install Jekyll (and Ruby) on your machine.  If you have Mac OS X 10.8 (Mountain Lion), our instructions at [HOWTO-Jekyll-MacOSX.txt ](https://github.com/SRI-CSL/stegotorus/raw/gh-pages/HOWTO-Jekyll-MacOSX.txt) might be useful.

To initialize your working copy, run:
```
$> bundle install
```

When editing the content for this site, you can preview things by changing the `url:` descriptor in `_config.yml` to `http://localhost:4000` (don't forget to change it back to `http://sri-csl.github.io/stegotorus` when committing to the `gh-pages` branch!) and then running:
```
$> bundle exec jekyll serve
```
Point your browser or reload [http://localhost:4000](http://localhost:4000).

## Notable features

* Stylesheet built using Sass. *Requires Jekyll 2.x*
* Data files for easier customization of the site navigation/footer and for supporting multiple authors.
