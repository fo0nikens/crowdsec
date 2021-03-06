## cscli config

Allows to view/edit cscli config

### Synopsis

Allow to configure sqlite path and installation directory.
If no commands are specified, config is in interactive mode.

### Examples

```
 - cscli config show
- cscli config prompt
```

### Options

```
  -h, --help   help for config
```

### Options inherited from parent commands

```
  -c, --config-dir string   Configuration directory to use. (default "/etc/crowdsec/cscli/")
      --debug               Set logging to debug.
      --error               Set logging to error.
      --info                Set logging to info.
  -o, --output string       Output format : human, json, raw. (default "human")
      --warning             Set logging to warning.
```

### SEE ALSO

* [cscli](cscli.md)	 - cscli allows you to manage crowdsec
* [cscli config backend](cscli_config_backend.md)	 - Configure installation directory
* [cscli config installdir](cscli_config_installdir.md)	 - Configure installation directory
* [cscli config prompt](cscli_config_prompt.md)	 - Prompt for configuration values in an interactive fashion
* [cscli config show](cscli_config_show.md)	 - Displays current config

###### Auto generated by spf13/cobra on 15-May-2020
