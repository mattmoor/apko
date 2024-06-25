// Copyright 2022, 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/spf13/cobra"
	"github.com/u-root/u-root/pkg/cpio"

	"github.com/chainguard-dev/clog"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/build/types"

	"golang.org/x/crypto/ssh"
)

func buildCPIO() *cobra.Command {
	var buildDate string
	var buildArch string
	var sbomPath string

	cmd := &cobra.Command{
		Use:     "build-cpio",
		Short:   "Build a cpio file from a YAML configuration file",
		Long:    "Build a cpio file from a YAML configuration file",
		Example: `  apko build-cpio <config.yaml> <output.cpio.gz>`,
		Hidden:  true,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return BuildCPIOCmd(cmd.Context(), args[1],
				build.WithConfig(args[0], []string{}),
				build.WithBuildDate(buildDate),
				build.WithSBOM(sbomPath),
				build.WithArch(types.ParseArchitecture(buildArch)),
			)
		},
	}

	cmd.Flags().StringVar(&buildDate, "build-date", "", "date used for the timestamps of the files inside the image")
	cmd.Flags().StringVar(&buildArch, "build-arch", runtime.GOARCH, "architecture to build for -- default is Go runtime architecture")
	cmd.Flags().StringVar(&sbomPath, "sbom-path", "", "generate an SBOM")

	return cmd
}

func BuildCPIOCmd(ctx context.Context, cpio string, opts ...build.Option) error {
	log := clog.FromContext(ctx)
	wd, err := os.MkdirTemp("", "apko-*")
	if err != nil {
		return fmt.Errorf("failed to create working directory: %w", err)
	}
	defer os.RemoveAll(wd)

	fs := apkfs.DirFS(wd, apkfs.WithCreateDir())
	bc, err := build.New(ctx, fs, opts...)
	if err != nil {
		return err
	}

	ic := bc.ImageConfiguration()

	if len(ic.Archs) != 0 {
		log.Warnf("ignoring archs in config, only building for current arch (%s)", bc.Arch())
	}

	_, layer, err := bc.BuildLayer(ctx)
	if err != nil {
		return fmt.Errorf("failed to build layer image: %w", err)
	}
	log.Debugf("converting layer to cpio %s", cpio)

	return LayerToCPIO(layer, cpio)
}

func LayerToCPIO(layer v1.Layer, cpioFile string) error {
	// Open the filesystem layer to walk through the file.
	u, err := layer.Uncompressed()
	if err != nil {
		return err
	}
	defer u.Close()
	tarReader := tar.NewReader(u)

	// Create the CPIO file, and set up a deduplicating writer
	// to produce the gzip-compressed CPIO archive.
	f, err := os.Create(cpioFile)
	if err != nil {
		return err
	}
	defer f.Close()
	gzipWriter := gzip.NewWriter(f)
	defer gzipWriter.Close()
	w := cpio.NewDedupWriter(cpio.Newc.Writer(gzipWriter))

	// Iterate through the tar archive entries
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			fmt.Println("Error reading tar entry:", err)
			return err
		}

		// Determine CPIO file mode based on TAR typeflag
		switch header.Typeflag {
		case tar.TypeDir:
			if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
				cpio.Directory(header.Name, uint64(header.Mode)),
			}); err != nil {
				return err
			}

		case tar.TypeSymlink:
			if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
				cpio.Symlink(header.Name, header.Linkname),
			}); err != nil {
				return err
			}

		case tar.TypeReg:
			var original bytes.Buffer
			// TODO(mattmoor): Do something better here, but unfortunately the
			// cpio stuff wants a seekable reader, so coming from a tar reader
			// I'm not sure how much leeway we have to do something better
			// than buffering.
			//nolint:gosec
			if _, err := io.Copy(&original, tarReader); err != nil {
				fmt.Println("Error reading file content:", err)
				return err
			}

			var content *bytes.Buffer

			// Copy unmodified files directly
			switch header.Name {

			// Boot straight to busybox shell as root (like a container!)
			case "usr/lib/systemd/system/serial-getty@.service":
				// Modify the target file
				content = bytes.NewBufferString(strings.ReplaceAll(
					original.String(),
					"ExecStart=",
					"ExecStart=-/bin/sh -l \n#",
				))

			// Disable systemd login; boot straight to busybox shell as root (like a container!)
			case "usr/lib/systemd/system/systemd-vconsole-setup.service":
				// Modify the target file
				content = bytes.NewBufferString(strings.ReplaceAll(
					original.String(),
					"ExecStart=",
					"ExecStart=/bin/true \n#",
				))

			// Enable pubkey login
			case "etc/ssh/sshd_config":
				// Modify the target file
				content = bytes.NewBufferString(strings.ReplaceAll(
					original.String(),
					"#PubkeyAuthentication",
					"PubkeyAuthentication",
				))

			default:
				content = &original
			}

			if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
				cpio.StaticFile(header.Name, content.String(), uint64(header.Mode)),
			}); err != nil {
				return err
			}

		case tar.TypeChar:
			if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
				cpio.CharDev(header.Name, uint64(header.Mode), uint64(header.Devmajor), uint64(header.Devminor)),
			}); err != nil {
				return err
			}

		default:
			fmt.Printf("Unsupported TAR typeflag: %c for %s\n", header.Typeflag, header.Name)
			continue // Skip unsupported types
		}
	}
	// Add a network configuration file
	if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
		cpio.StaticFile("etc/systemd/network/20-wired.network", `[Match]
		Name=en*
		[Network]
		DHCP=yes
		`, 0o777)}); err != nil {
		return err
	}

	// Create a new SSH key pair for the client
	pub, priv, err := ed25519.GenerateKey(nil) // NB: If rand is nil, crypto/rand.Reader will be used
	if err != nil {
		return fmt.Errorf("failed to generate ed25519 key pair: %w", err)
	}
	p, err := ssh.MarshalPrivateKey(crypto.PrivateKey(priv), "")
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	privateKeyPem := pem.EncodeToMemory(p)
	privateKeyString := string(privateKeyPem)
	publicKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		return fmt.Errorf("failed to generate public key: %w", err)
	}
	publicKeyString := "ssh-ed25519" + " " + base64.StdEncoding.EncodeToString(publicKey.Marshal())
	fmt.Printf("Private Key:\n%s\n", privateKeyString)

	// Put this into a tmp file to make it easier to ssh into the qemu instance
	// this is 600 so ssh doesn't complain about the permissions.
	// This should somehow be plumbed in memory to the qemu runner, or something.
	//nolint:gosec
	if err := os.WriteFile("/tmp/qemu-private", []byte(privateKeyString), 0600); err != nil {
		return fmt.Errorf("failed to write private key file: %w", err)
	}

	fmt.Printf("Public Key:\n%s\n", publicKeyString)
	if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
		cpio.StaticFile("root/.ssh/authorized_keys", publicKeyString, 0o600)}); err != nil {
		return fmt.Errorf("failed to write authorized_keys file: %w", err)
	}

	// Create a new _host_ SSH key pair for the server
	// We need to do this because the apk package for openssh-server has a
	// scriptlet that generates the host keys, and that doesn't get executed
	// when apko installs it. So, just generate the ed25529 key pair here.
	hostPub, hostPriv, err := ed25519.GenerateKey(nil) // NB: If rand is nil, crypto/rand.Reader will be used
	if err != nil {
		return fmt.Errorf("failed to generate ed25519 host key pair: %w", err)
	}
	hostP, err := ssh.MarshalPrivateKey(crypto.PrivateKey(hostPriv), "")
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	hostPrivateKeyPem := pem.EncodeToMemory(hostP)
	hostPrivateKeyString := string(hostPrivateKeyPem)
	hostPublicKey, err := ssh.NewPublicKey(hostPub)
	if err != nil {
		return fmt.Errorf("failed to generate host public key: %w", err)
	}
	hostPublicKeyString := "ssh-ed25519" + " " + base64.StdEncoding.EncodeToString(hostPublicKey.Marshal())
	knownHostKeyString := "[localhost]:1234 " + hostPublicKeyString
	fmt.Printf("Host Private Key:\n%s\n", hostPrivateKeyString)
	fmt.Printf("Host Public Key:\n%s\n", hostPublicKeyString)
	fmt.Printf("Known Host key:\n%s\n", knownHostKeyString)
	// Put the known host into a tmp file to make it easier to ssh into the
	// qemu instance
	// This should somehow be plumbed in memory to the qemu runner, or something.
	//nolint:gosec
	if err := os.WriteFile("/tmp/qemu-known-hosts", []byte(knownHostKeyString), 0600); err != nil {
		return fmt.Errorf("failed to write private key file: %w", err)
	}

	if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
		cpio.StaticFile("etc/ssh/ssh_host_ed25519_key.pub", hostPublicKeyString, 0o644)}); err != nil {
		return fmt.Errorf("failed to write host pub key file: %w", err)
	}
	if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
		cpio.StaticFile("etc/ssh/ssh_host_ed25519_key", hostPrivateKeyString, 0o600)}); err != nil {
		return fmt.Errorf("failed to write host private key file: %w", err)
	}

	// Add sshd service file
	// Note the hack in ExecStart to make sure the /root/.ssh directory is
	// created with the correct permissions before starting sshd.
	if err := cpio.WriteRecordsAndDirs(w, []cpio.Record{
		cpio.StaticFile("usr/lib/systemd/system/sshd.service", `[Unit]
		Description=OpenSSH server daemon
		After=syslog.target network.target auditd.service

		[Service]
		ExecStartPre=/bin/chmod 700 /root/.ssh
		ExecStart=/usr/sbin/sshd -E /tmp/sshd.log -D

		[Install]
		WantedBy=multi-user.target
		`, 0o777)}); err != nil {
		return err
	}

	return w.WriteRecord(cpio.TrailerRecord)
}
