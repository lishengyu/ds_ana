package yamlreader

import (
	"fmt"

	"github.com/spf13/viper"
)

type Reader struct {
	v *viper.Viper
}

func NewReader(conf string) (*Reader, error) {
	v := viper.New()

	v.SetConfigFile(conf)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file")
	}

	return &Reader{v: v}, nil
}

func (r *Reader) GetString(key string) string {
	return r.v.GetString(key)
}

func (r *Reader) GetInt(key string) int {
	return r.v.GetInt(key)
}

func (r *Reader) GetBool(key string) bool {
	return r.v.GetBool(key)
}
