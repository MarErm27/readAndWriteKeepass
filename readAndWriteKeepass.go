package readAndWriteKeepass

import (
	"fmt"
	//"log"
	"os"

	"github.com/tobischo/gokeepasslib"
	w "github.com/tobischo/gokeepasslib/wrappers"

	"github.com/MarErm27/getCertificateData"
)

func mkValue(key string, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{Key: key, Value: gokeepasslib.V{Content: value}}
}

func mkProtectedValue(key string, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{
		Key:   key,
		Value: gokeepasslib.V{Content: value, Protected: w.NewBoolWrapper(true)},
	}
}
func createSubGroups(rootGroup *gokeepasslib.Group, s **[][]map[string]getCertificateData.Vertex) {
	subGroup := gokeepasslib.NewGroup()
	subGroup.Name = "Новые сертификаты"
	for _, c := range **s {
		subEntry := gokeepasslib.NewEntry()
		for _, value := range c {

			for entryName, entryValue := range value {

				subEntry.Values = append(subEntry.Values, mkValue(entryName, entryValue.Value))
				//fmt.Println(certNumber, entryNumber, entryName, entryValue.Value)
			}

		}
		subGroup.Entries = append(subGroup.Entries, subEntry)

	}
	rootGroup.Groups = append(rootGroup.Groups, subGroup)
}

// // VL commented
// type VL []int
// // GetValues commented
// func (v VL) GetValues() string{
// 	return "values"
// }
// // Thing commented
// type Thing struct {
// 	Value VL
// }
// func test(){
// 	entry := Thing{}
// 	fmt.Println(entry)
// 	entry.Values.
// }

func checkSerts(rootGroup *gokeepasslib.Group, s **[][]map[string]getCertificateData.Vertex) {
	//rootGroup
	for subGroupNumber, subGroup := range rootGroup.Groups {
		for entryNumber, entry := range subGroup.Entries {

			for entryFieldNumber, entryField := range entry.Values {
				fmt.Println(subGroupNumber, entryNumber, entryFieldNumber, entryField.Key, entryField.Value.Content)

				if entryField.Key == "Fingerprint" {
					fmt.Println("--------------------------")
					continue
				}
			}

			// fmt.Println(subGroupNumber, entryNumber, entry.Values[0].Key)

			// fmt.Println("--------------------------entry.Values[0].Key")
		}
	}
}

func ReadFromKeepass() gokeepasslib.Group {
	masterPassword := "supersecret"
	writeFilename := "example-deleting.kdbx"
	readFile, err := os.Open(writeFilename)
	if err != nil {
		//panic(err)
		readFile, err = os.Create(writeFilename)
		if err != nil {
			panic(err)
		}
		// create root group
		rootGroup := gokeepasslib.NewGroup()
		rootGroup.Name = "root group"

		entry := gokeepasslib.NewEntry()
		entry.Values = append(entry.Values, mkValue("Title", "My GMail password"))
		entry.Values = append(entry.Values, mkValue("UserName", "example@gmail.com"))
		entry.Values = append(entry.Values, mkProtectedValue("Password", "hunter2"))

		rootGroup.Entries = append(rootGroup.Entries, entry)

		// demonstrate creating sub group (we'll leave it empty because we're lazy)
		subGroup := gokeepasslib.NewGroup()
		subGroup.Name = "sub group"

		subEntry := gokeepasslib.NewEntry()
		subEntry.Values = append(subEntry.Values, mkValue("Title", "Another password"))
		subEntry.Values = append(subEntry.Values, mkValue("UserName", "johndough"))
		subEntry.Values = append(subEntry.Values, mkProtectedValue("Password", "123456"))

		subGroup.Entries = append(subGroup.Entries, subEntry)

		rootGroup.Groups = append(rootGroup.Groups, subGroup)

		subGroupNewCerts := gokeepasslib.NewGroup()
		subGroupNewCerts.Name = "Новые сертификаты"

		// subEntry := gokeepasslib.NewEntry()
		// subEntry.Values = append(subEntry.Values, mkValue("Title", "Another password"))
		// subEntry.Values = append(subEntry.Values, mkValue("UserName", "johndough"))
		// subEntry.Values = append(subEntry.Values, mkProtectedValue("Password", "123456"))

		// subGroupNewCerts.Entries = append(subGroupNewCerts.Entries, subEntry)
		rootGroup.Groups = append(rootGroup.Groups, subGroupNewCerts)
		// now create the database containing the root group
		db := &gokeepasslib.Database{
			Header:      gokeepasslib.NewHeader(),
			Credentials: gokeepasslib.NewPasswordCredentials(masterPassword),
			Content: &gokeepasslib.DBContent{
				Meta: gokeepasslib.NewMetaData(),
				Root: &gokeepasslib.RootData{
					Groups: []gokeepasslib.Group{rootGroup},
				},
			},
		}

		// Lock entries using stream cipher
		db.LockProtectedEntries()

		// and encode it into the file
		keepassEncoder := gokeepasslib.NewEncoder(readFile)
		if err := keepassEncoder.Encode(db); err != nil {
			panic(err)
		}

		readFile, err = os.Open(writeFilename)
		if err != nil {
			panic(err)
		}
		//defer file.Close()
	}
	defer readFile.Close()
	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(masterPassword)
	err = gokeepasslib.NewDecoder(readFile).Decode(db)
	if err != nil {
		panic(err)
	}
	// Unlock protected entries to handle stream cipher
	db.UnlockProtectedEntries()

	rootGroup := db.Content.Root.Groups[0]
	return rootGroup
}

func WriteToKeepass(s *[][]map[string]getCertificateData.Vertex) {
	//s := getCertificateData.GetSlice()
	// for certNumber, c := range *s{
	//  for entryNumber, value := range c{
	//    for entryName, entryValue := range value{
	//      fmt.Println(certNumber, entryNumber, entryName, entryValue.Value)
	//    }
	//  }
	//  fmt.Println("----------------------")
	// }
	// fmt.Println("FINISH")

	//fmt.Println("FINISH")
	readFilename := "example-writing.kdbx"
	writeFilename := "example-deleting.kdbx"
	masterPassword := "supersecret"

	readFile, err := os.Open(readFilename)
	if err != nil {
		readFile, err = os.Create(readFilename)
		if err != nil {
			panic(err)
		}
		// create root group
		rootGroup := gokeepasslib.NewGroup()
		rootGroup.Name = "root group"

		entry := gokeepasslib.NewEntry()
		entry.Values = append(entry.Values, mkValue("Title", "My GMail password"))
		entry.Values = append(entry.Values, mkValue("UserName", "example@gmail.com"))
		entry.Values = append(entry.Values, mkProtectedValue("Password", "hunter2"))

		rootGroup.Entries = append(rootGroup.Entries, entry)

		// demonstrate creating sub group (we'll leave it empty because we're lazy)
		subGroup := gokeepasslib.NewGroup()
		subGroup.Name = "sub group"

		subEntry := gokeepasslib.NewEntry()
		subEntry.Values = append(subEntry.Values, mkValue("Title", "Another password"))
		subEntry.Values = append(subEntry.Values, mkValue("UserName", "johndough"))
		subEntry.Values = append(subEntry.Values, mkProtectedValue("Password", "123456"))

		subGroup.Entries = append(subGroup.Entries, subEntry)

		rootGroup.Groups = append(rootGroup.Groups, subGroup)

		// subGroupNewCerts := gokeepasslib.NewGroup()
		// subGroupNewCerts.Name = "Новые сертификаты"

		// // subEntry := gokeepasslib.NewEntry()
		// // subEntry.Values = append(subEntry.Values, mkValue("Title", "Another password"))
		// // subEntry.Values = append(subEntry.Values, mkValue("UserName", "johndough"))
		// // subEntry.Values = append(subEntry.Values, mkProtectedValue("Password", "123456"))

		// // subGroupNewCerts.Entries = append(subGroupNewCerts.Entries, subEntry)
		// rootGroup.Groups = append(rootGroup.Groups, subGroupNewCerts)
		// now create the database containing the root group
		db := &gokeepasslib.Database{
			Header:      gokeepasslib.NewHeader(),
			Credentials: gokeepasslib.NewPasswordCredentials(masterPassword),
			Content: &gokeepasslib.DBContent{
				Meta: gokeepasslib.NewMetaData(),
				Root: &gokeepasslib.RootData{
					Groups: []gokeepasslib.Group{rootGroup},
				},
			},
		}

		// Lock entries using stream cipher
		db.LockProtectedEntries()

		// and encode it into the file
		keepassEncoder := gokeepasslib.NewEncoder(readFile)
		if err := keepassEncoder.Encode(db); err != nil {
			panic(err)
		}

		readFile, err = os.Open(readFilename)
		if err != nil {
			panic(err)
		}
	}
	defer readFile.Close()

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(masterPassword)
	err = gokeepasslib.NewDecoder(readFile).Decode(db)
	if err != nil {
		panic(err)
	}

	// Unlock protected entries to handle stream cipher
	db.UnlockProtectedEntries()

	rootGroup := db.Content.Root.Groups[0]
	createSubGroups(&rootGroup, &s)
	//scheckSerts(&rootGroup, &s)
	// Remove `My GMail password` entry from example-writing example
	//rootGroup.Entries = rootGroup.Entries[:0]

	db.Content.Root.Groups[0] = rootGroup

	// Lock entries using stream cipher
	db.LockProtectedEntries()

	writeFile, err := os.Create(writeFilename)
	if err != nil {
		panic(err)
	}
	defer writeFile.Close()

	// and encode it into the file
	keepassEncoder := gokeepasslib.NewEncoder(writeFile)
	if err := keepassEncoder.Encode(db); err != nil {
		panic(err)
	}

}
