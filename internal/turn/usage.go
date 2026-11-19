package turn

import (
	"encoding/json"
	"strings"

	"github.com/GetKlaros/nia-edge/canon"
)

// Usage is what a model call used, as its provider reports it: every input
// token (cached ones included), the cached input tokens among them, and the
// output tokens.
type Usage struct {
	InputTokens       int `json:"input_tokens"`
	CachedInputTokens int `json:"cached_input_tokens"`
	OutputTokens      int `json:"output_tokens"`
}

type chatUsage struct {
	Prompt     *int `json:"prompt_tokens"`
	Completion *int `json:"completion_tokens"`
	Details    *struct {
		Cached int `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
}

type responsesUsage struct {
	Input   *int `json:"input_tokens"`
	Output  *int `json:"output_tokens"`
	Details *struct {
		Cached int `json:"cached_tokens"`
	} `json:"input_tokens_details"`
}

// Anthropic counts cache reads and writes apart from input_tokens.
type anthropicUsage struct {
	Input       *int `json:"input_tokens"`
	Output      *int `json:"output_tokens"`
	CacheRead   int  `json:"cache_read_input_tokens"`
	CacheCreate int  `json:"cache_creation_input_tokens"`
}

func (u chatUsage) usage() (Usage, bool) {
	if u.Prompt == nil || u.Completion == nil {
		return Usage{}, false
	}
	usage := Usage{InputTokens: *u.Prompt, OutputTokens: *u.Completion}
	if u.Details != nil {
		usage.CachedInputTokens = u.Details.Cached
	}
	return usage, true
}

func (u responsesUsage) usage() (Usage, bool) {
	if u.Input == nil || u.Output == nil {
		return Usage{}, false
	}
	usage := Usage{InputTokens: *u.Input, OutputTokens: *u.Output}
	if u.Details != nil {
		usage.CachedInputTokens = u.Details.Cached
	}
	return usage, true
}

// ReadUsage reads the tokens a provider's answer reports. ok is false when it
// reports none, or not in a shape this code knows: then the call cannot be
// counted.
func ReadUsage(format Format, stream bool, body string) (usage Usage, ok bool) {
	if !stream {
		switch format {
		case ChatCompletions:
			var answer struct{ Usage *chatUsage }
			if json.Unmarshal([]byte(body), &answer) != nil || answer.Usage == nil {
				return Usage{}, false
			}
			return answer.Usage.usage()
		case Responses:
			var answer struct{ Usage *responsesUsage }
			if json.Unmarshal([]byte(body), &answer) != nil || answer.Usage == nil {
				return Usage{}, false
			}
			return answer.Usage.usage()
		case AnthropicMessages:
			var answer struct{ Usage *anthropicUsage }
			if json.Unmarshal([]byte(body), &answer) != nil || answer.Usage == nil || answer.Usage.Input == nil || answer.Usage.Output == nil {
				return Usage{}, false
			}
			u := answer.Usage
			return Usage{InputTokens: *u.Input + u.CacheRead + u.CacheCreate, CachedInputTokens: u.CacheRead, OutputTokens: *u.Output}, true
		}
		return Usage{}, false
	}
	var input, cacheRead, cacheCreate, output *int
	found := false
	for _, data := range sseData(body) {
		switch format {
		case ChatCompletions:
			// The last chunk carries the usage of the whole call.
			var chunk struct{ Usage *chatUsage }
			if json.Unmarshal([]byte(data), &chunk) == nil && chunk.Usage != nil {
				if u, ok := chunk.Usage.usage(); ok {
					usage, found = u, true
				}
			}
		case Responses:
			var event struct {
				Type     string
				Response *struct{ Usage *responsesUsage }
			}
			if json.Unmarshal([]byte(data), &event) == nil && event.Response != nil && event.Response.Usage != nil &&
				(event.Type == "response.completed" || event.Type == "response.incomplete" || event.Type == "response.failed") {
				if u, ok := event.Response.Usage.usage(); ok {
					usage, found = u, true
				}
			}
		case AnthropicMessages:
			var event struct {
				Type    string
				Message *struct{ Usage *anthropicUsage }
				Usage   *anthropicUsage
			}
			if json.Unmarshal([]byte(data), &event) != nil {
				continue
			}
			take := func(u *anthropicUsage) {
				if u == nil {
					return
				}
				if u.Input != nil {
					input = u.Input
				}
				if u.Output != nil {
					output = u.Output
				}
				if u.CacheRead > 0 {
					cacheRead = &u.CacheRead
				}
				if u.CacheCreate > 0 {
					cacheCreate = &u.CacheCreate
				}
			}
			if event.Type == "message_start" && event.Message != nil {
				take(event.Message.Usage)
			}
			// message_delta's counts are cumulative.
			if event.Type == "message_delta" {
				take(event.Usage)
			}
		}
	}
	if format == AnthropicMessages {
		if input == nil || output == nil {
			return Usage{}, false
		}
		read, create := 0, 0
		if cacheRead != nil {
			read = *cacheRead
		}
		if cacheCreate != nil {
			create = *cacheCreate
		}
		return Usage{InputTokens: *input + read + create, CachedInputTokens: read, OutputTokens: *output}, true
	}
	return usage, found
}

// sseData returns the data of each event of a stream, in order.
func sseData(body string) []string {
	var out []string
	for _, block := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n\n") {
		var lines []string
		for _, line := range strings.Split(block, "\n") {
			if rest, ok := strings.CutPrefix(line, "data:"); ok {
				lines = append(lines, strings.TrimPrefix(rest, " "))
			}
		}
		if len(lines) > 0 {
			out = append(out, strings.Join(lines, "\n"))
		}
	}
	return out
}

// AskUsage makes a streamed Chat Completions request report its usage
// (stream_options.include_usage): the provider sends it in one more chunk,
// whose choices are empty. It reports whether the request changed.
func AskUsage(format Format, body *canon.Value) bool {
	if format != ChatCompletions {
		return false
	}
	if stream, _ := body.Get("stream").Truth(); !stream {
		return false
	}
	yes, _ := canon.Parse("true")
	options := body.Get("stream_options")
	if options.Kind() == canon.Object {
		if include, _ := options.Get("include_usage").Truth(); include {
			return false
		}
		options.Set("include_usage", yes)
		return true
	}
	object, _ := canon.Parse(`{"include_usage":true}`)
	body.Set("stream_options", object)
	return true
}
