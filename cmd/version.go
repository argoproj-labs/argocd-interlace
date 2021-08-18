package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "argocd-interlace version",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		log.Info("argocd-interlace 0.0.1")
	},
}
