package extractor

import (
	"strings"
	"unicode/utf8"
)

func buildLineStarts(data string) []int {
	starts := []int{0}
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

func lineColumn(lineStarts []int, offset int) (line, col int) {
	line = 1
	col = offset + 1
	for i := len(lineStarts) - 1; i >= 0; i-- {
		if lineStarts[i] <= offset {
			line = i + 1
			col = offset - lineStarts[i] + 1
			return line, col
		}
	}
	return line, col
}

func snippetAt(data string, lineStarts []int, start, end int) string {
	startLine, _ := lineColumn(lineStarts, start)
	endLine, _ := lineColumn(lineStarts, end)

	begin := lineStarts[startLine-1]
	finish := len(data)
	if endLine < len(lineStarts) {
		finish = lineStarts[endLine]
	}
	s := strings.TrimRight(data[begin:finish], "\r\n")
	if utf8.RuneCountInString(s) > 200 {
		runes := []rune(s)
		s = string(runes[:200]) + "..."
	}
	return s
}

func findingAt(data string, lineStarts []int, source, ruleID string, start, end int) modelFindingLoc {
	value := data[start:end]
	sl, sc := lineColumn(lineStarts, start)
	el, ec := lineColumn(lineStarts, end-1)
	return modelFindingLoc{
		value:     value,
		source:    source,
		ruleID:    ruleID,
		startLine: sl,
		endLine:   el,
		startCol:  sc,
		endCol:    ec,
		snippet:   snippetAt(data, lineStarts, start, end),
	}
}

type modelFindingLoc struct {
	value     string
	source    string
	ruleID    string
	startLine int
	endLine   int
	startCol  int
	endCol    int
	snippet   string
}
