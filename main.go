/*
 * Copyright (c) 2026 Ruiyuan "mizumoto-cn" Xu
 *
 * Licensed under the Mizumoto General Public License v1.5.
 * See the LICENSE file in the project root for full license information.
 */

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/mizumoto-cn/mizuenc/pkg"
)

func main() {
	app := &cli.Command{
		Name:  "mizuenc",
		Usage: "Encrypt/decrypt data with AES-256-GCM (PBKDF2-derived key).",
		Commands: []*cli.Command{
			{
				Name:      "encrypt",
				Usage:     "Encrypt a string and print the token",
				ArgsUsage: "<plaintext>",
				Action: func(_ context.Context, cmd *cli.Command) error {
					arg := cmd.Args().Get(0)
					if arg == "" {
						return fmt.Errorf("missing plaintext argument")
					}
					plaintext := []byte(arg)
					token, err := pkg.DefaultEncrypter.Encrypt(plaintext)
					if err != nil {
						return err
					}
					_, _ = fmt.Fprintln(os.Stdout, string(token))
					return nil
				},
			},
			{
				Name:      "decrypt",
				Usage:     "Decrypt a token and print the plaintext",
				ArgsUsage: "<token>",
				Action: func(_ context.Context, cmd *cli.Command) error {
					arg := cmd.Args().Get(0)
					if arg == "" {
						return fmt.Errorf("missing token argument")
					}
					token := []byte(arg)
					plaintext, err := pkg.DefaultEncrypter.Decrypt(token)
					if err != nil {
						return err
					}
					_, _ = fmt.Fprintln(os.Stdout, string(plaintext))
					return nil
				},
			},
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
