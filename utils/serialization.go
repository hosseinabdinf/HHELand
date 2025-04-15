package utils

import (
	"encoding"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

func Serialize(object any, path string) (err error) {

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("os.Create(%s): %w", path, err)
	}

	defer f.Close()

	switch object := object.(type) {
	case io.WriterTo:
		if _, err = object.WriteTo(f); err != nil {
			return fmt.Errorf("%T.WriteTo: %w", object, err)
		}
	case encoding.BinaryMarshaler:
		var data []byte
		if data, err = object.MarshalBinary(); err != nil {
			return fmt.Errorf("%T.MarshalBinary: %w", object, err)
		}
		if _, err = f.Write(data); err != nil {
			return fmt.Errorf("file.Write: %w", err)
		}
	default:
		return fmt.Errorf("%T does not implement io.WriterTo or encoding.BinaryMarshaler", object)
	}

	return
}

func Deserialize(object any, path string) (err error) {

	switch object := object.(type) {
	case io.ReaderFrom:
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("os.Open(%s): %w", path, err)
		}
		defer f.Close()

		if _, err = object.ReadFrom(f); err != nil {
			return fmt.Errorf("%T.ReadFrom: %w", object, err)
		}
	case encoding.BinaryUnmarshaler:
		var data []byte
		if data, err = os.ReadFile(path); err != nil {
			return fmt.Errorf("os.ReadFile(%s): %w", path, err)
		}

		if err = object.UnmarshalBinary(data); err != nil {
			return fmt.Errorf("%T.UnmarshalBinary: %w", object, err)
		}

	default:
		return fmt.Errorf("%T does not implement io.ReaderFrom or encoding.BinaryUnmarshaler", object)
	}

	return
}

func MarshalJSON(object any) (data []byte, err error) {
	return json.Marshal(object)
}

func UnMarshalJSON(data []byte) (object any, err error) {
	if err = json.Unmarshal(data, &object); err != nil {
		return nil, fmt.Errorf("json.Unmarshal: %w", err)
	} else {
		return object, nil
	}
}
